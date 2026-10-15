"""Host observation shapes of FinishUP's own calls and of edits, classified by ``later_material_class``.

tb4n3 RC-6 (issue #1029): ``check_current_as_of_earlier_frontier`` was added for every record that
followed the last check, so 17 of 17 tb4n3 receipts carried it and a post-check edit looked like a
status poll. The class rule reads the *materialized* ledger rows, so this module sends real hook
payloads of all three hosts through the real ingress and the real materializer and classifies the
rows that come out. Nothing here hand-writes an action description.

Host decisions pinned here (and recorded in docs/runbooks/*-integration.md):

* Codex: ``mcp__finishup__<tool>`` from hooks and, since #1038, from the rollout's ``McpToolCall``
  (its ``server`` is kept); the bare ``<tool>`` only from an item that names no server.
* Claude Code: ``mcp__plugin_finishup_finishup__<tool>``.
* Cursor: ``finishup:<tool>`` / ``plugin-finishup-finishup:<tool>`` when the server is named; the ordinary
  profile's generic ``MCP:<tool>`` names no server and is read by the closed FinishUP basenames.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import io
from collections.abc import Callable, Iterator
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest

from builders.observed_runs import INSTALLATION_KEY, ObservedLedger
from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.application.observation_materialize import materialize_observation_envelope
from finishup.cli import observe_hooks
from finishup.domain.events import (
    AcceptedEvent,
    ActionRecordedPayload,
    EventPayload,
    EventSchema,
    EvidenceRecordedPayload,
    ResultRecordedPayload,
)
from finishup.domain.observation import ObservationEnvelope
from finishup.domain.observation_profiles import (
    CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
    CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
)
from finishup.domain.values import JsonObject, Timestamp
from finishup.kernel.later_material import LaterMaterialClass, classify_later_material
from finishup.kernel.reducers import replay
from finishup.kernel.task_facts import register_command_identity_key
from finishup.protocol.canonical import canonical_encode

_TASK = "tsk_7a3f1c52-6a0e-4c1b-9d2e-8b5f4a3c2d10"
_KEY = bytes(range(32))
_RECEIPT = Timestamp("2026-09-29T17:55:00.957Z")
_C = LaterMaterialClass

type _Hook1 = tuple[str, dict[str, Any], str | None]
# One tool call is its pre-event then its post-event: a paired profile records the call as one
# action and its result only when both arrive.
type _Hook = tuple[_Hook1, ...]


def _codex(tool: str, call: str, tool_input: dict[str, Any], tool_response: Any) -> _Hook:
    def one(event: str, **fields: Any) -> _Hook1:
        payload = {
            "cwd": "/app",
            "hook_event_name": event,
            "model": "gpt-6-sol",
            "permission_mode": "bypassPermissions",
            "session_id": "019f9b27-c1de-7a61-9c5e-5d0b89759417",
            "tool_name": tool,
            "tool_use_id": call,
            "tool_input": tool_input,
            **fields,
        }
        return event, payload, None

    return one("PreToolUse"), one("PostToolUse", tool_response=tool_response)


def _claude(tool: str, tool_input: dict[str, Any], call: str) -> _Hook:
    def one(event: str, **fields: Any) -> _Hook1:
        return (
            event,
            {
                "cwd": "/app",
                "hook_event_name": event,
                "permission_mode": "default",
                "session_id": "7c1e2f4a-claude-session",
                "tool_input": tool_input,
                "tool_name": tool,
                "tool_use_id": call,
                "transcript_path": "/private/transcript.jsonl",
                **fields,
            },
            CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
        )

    return one("PreToolUse"), one(
        "PostToolUse", tool_response={"content": [{"text": "ok", "type": "text"}]}
    )


def _cursor(tool: str, tool_input: dict[str, Any], call: str) -> _Hook:
    def one(event: str, **fields: Any) -> _Hook1:
        return (
            event,
            {
                "conversation_id": "c0ffee00-cursor-conversation",
                "cursor_version": "3.20.0",
                "generation_id": f"gen-{call}",
                "hook_event_name": event,
                "session_id": "c0ffee00-cursor-conversation",
                "tool_input": tool_input,
                "tool_name": tool,
                "tool_use_id": call,
                "workspace_roots": [],
                **fields,
            },
            CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
        )

    return one("preToolUse"), one("postToolUse", tool_output='{"exitCode":0}')


_OK = {"content": [{"text": "ok", "type": "text"}], "isError": False}
_CODEX_HOOKS: tuple[tuple[str, _Hook, _C], ...] = (
    (
        "codex check (a mutation: its post lands after check_recorded)",
        _codex("mcp__finishup__check", "call_c1", {"mode": "deterministic_only"}, _OK),
        _C.FINISHUP_OWN_CALL,
    ),
    (
        "codex status read",
        _codex("mcp__finishup__status", "call_s1", {"view": "findings"}, _OK),
        _C.FINISHUP_OWN_CALL,
    ),
    (
        "codex read_guidance",
        _codex(
            "mcp__finishup__read_guidance",
            "call_g1",
            {"uri": "finishup://guidance/receipt.md"},
            _OK,
        ),
        _C.FINISHUP_OWN_CALL,
    ),
    (
        "codex receipt",
        _codex("mcp__finishup__receipt", "call_r1", {"format": "json"}, _OK),
        _C.FINISHUP_OWN_CALL,
    ),
    (
        "codex wait (a poll of a code-mode cell started earlier)",
        _codex("wait", "call_w1", {"cell_id": "94", "yield_time_ms": 1000}, "cell output"),
        _C.NO_TOOL_ACTIVITY,
    ),
    (
        # tb4n5 react S: the agent slept while its check cell ran; two sleeps bounded the check.
        "codex clock.sleep (hook spelling clocksleep; it only pauses the turn)",
        _codex(
            "clocksleep",
            "call_z1",
            {"duration_ms": 20000},
            "Wall time: 20.0036 seconds\nSleep completed.",
        ),
        _C.NO_TOOL_ACTIVITY,
    ),
    (
        "codex cat (exploration)",
        _codex("Bash", "call_x1", {"command": "cat results.json"}, '{"exit_code":0,"output":"{}"}'),
        _C.EXPLORATION,
    ),
    (
        "codex pytest (a verification run is not proven read-only)",
        _codex("Bash", "call_t1", {"command": "pytest -q"}, '{"exit_code":0,"output":"3 passed"}'),
        _C.OTHER,
    ),
    (
        "codex apply_patch to a deliverable",
        _codex(
            "apply_patch",
            "call_p1",
            {"command": "*** Begin Patch\n*** Update File: out.json\n@@\n-a\n+b\n*** End Patch"},
            "Exit code: 0\nWall time: 0.1 seconds\nOutput:\nSuccess.",
        ),
        _C.EDIT_OR_WRITE,
    ),
    (
        "codex apply_patch saving finishup_receipt.md",
        _codex(
            "apply_patch",
            "call_p2",
            {
                "command": "*** Begin Patch\n*** Add File: /app/finishup_receipt.md\n+x\n*** End Patch"
            },
            "Exit code: 0\nWall time: 0.1 seconds\nOutput:\nSuccess.",
        ),
        _C.NON_COUNTING_WRITE,
    ),
)

_CLAUDE_HOOKS: tuple[tuple[str, _Hook, _C], ...] = (
    (
        "claude check",
        _claude("mcp__plugin_finishup_finishup__check", {}, "toolu_c"),
        _C.FINISHUP_OWN_CALL,
    ),
    (
        "claude status",
        _claude("mcp__plugin_finishup_finishup__status", {}, "toolu_s"),
        _C.FINISHUP_OWN_CALL,
    ),
    (
        "claude receipt",
        _claude("mcp__plugin_finishup_finishup__receipt", {}, "toolu_r"),
        _C.FINISHUP_OWN_CALL,
    ),
    (
        "claude Read (native read tool)",
        _claude("Read", {"file_path": "/app/out.json"}, "toolu_read"),
        _C.EXPLORATION,
    ),
    (
        "claude Edit of a deliverable",
        _claude(
            "Edit", {"file_path": "/app/out.json", "old_string": "a", "new_string": "b"}, "toolu_e"
        ),
        _C.EDIT_OR_WRITE,
    ),
    (
        "claude Write of finishup_receipt.md",
        _claude("Write", {"file_path": "/app/finishup_receipt.md", "content": "x"}, "toolu_w"),
        _C.NON_COUNTING_WRITE,
    ),
    (
        "claude Bash python script",
        _claude("Bash", {"command": "python gen.py"}, "toolu_b"),
        _C.OTHER,
    ),
)

_CURSOR_HOOKS: tuple[tuple[str, _Hook, _C], ...] = (
    (
        "cursor server-scoped check",
        _cursor("plugin-finishup-finishup:check", {}, "cur_c"),
        _C.FINISHUP_OWN_CALL,
    ),
    ("cursor finishup: status", _cursor("finishup:status", {}, "cur_s"), _C.FINISHUP_OWN_CALL),
    (
        "cursor generic MCP:check (no server named; read by the closed FinishUP basenames)",
        _cursor("MCP:check", {}, "cur_gc"),
        _C.FINISHUP_OWN_CALL,
    ),
    ("cursor generic MCP:status", _cursor("MCP:status", {}, "cur_gs"), _C.FINISHUP_OWN_CALL),
    (
        "cursor generic MCP tool of another name stays disclosed",
        _cursor("MCP:fetch_rows", {}, "cur_gf"),
        _C.OTHER,
    ),
    (
        "cursor Write of a deliverable",
        _cursor("Write", {"path": "/app/out.json", "contents": "x"}, "cur_w"),
        _C.EDIT_OR_WRITE,
    ),
    (
        "cursor Shell ls (exploration)",
        _cursor("Shell", {"command": "ls -la"}, "cur_l"),
        _C.EXPLORATION,
    ),
)


def _fixed_key(_store: LocalObservationStore) -> bytes:
    return _KEY


def _ingest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    handler: Callable[..., int],
    hook: _Hook,
) -> tuple[ObservationEnvelope, ...]:
    monkeypatch.setattr(LocalObservationStore, "key_material", _fixed_key)
    workspace = tmp_path / "app"
    workspace.mkdir(exist_ok=True)
    root = tmp_path / "isolated"
    store = LocalObservationStore(_state=root)
    commitment = store.workspace_commitment(str(workspace.resolve()))
    store.grant_consent(commitment)
    for event, payload, profile in hook:
        kwargs: dict[str, Any] = {}
        if handler is not observe_hooks.handle_observe:
            kwargs["observation_profile"] = profile
        assert (
            handler(
                event_name=event,
                stdin_bytes=canonical_encode(JsonObject(payload)),
                stdout=io.BytesIO(),
                workspace=str(workspace),
                _state=root,
                skip_service=True,
                **kwargs,
            )
            == 0
        )
    # ``list_envelopes`` includes the envelopes the self-observation policy (#564) keeps local, so
    # the classification of a FinishUP read is exercised even though it is never delivered.
    return tuple(replace(item, receipt_time=_RECEIPT) for item in store.list_envelopes(commitment))


def _classes(envelopes: tuple[ObservationEnvelope, ...]) -> tuple[_C, ...]:
    """Materialize the envelopes and classify the observed rows they produce."""

    ledger = ObservedLedger()
    for envelope in envelopes:
        batch = materialize_observation_envelope(envelope, task_id=_TASK)
        for draft in batch.drafts:
            payload = draft.draft.payload
            if type(payload) in {ActionRecordedPayload, ResultRecordedPayload}:
                ledger.append(
                    EventSchema(draft.draft.schema.name, draft.draft.schema.version),
                    cast(EventPayload, payload),
                    observed=True,
                )
    records = ledger.prefix
    assert records, "the hook produced no action or result row"
    projection = replay(records)
    return tuple(classify_later_material(record, projection).material_class for record in records)


@pytest.fixture(autouse=True)
def identity_key() -> Iterator[None]:
    register_command_identity_key(INSTALLATION_KEY)
    yield
    register_command_identity_key(None)


@pytest.mark.parametrize(
    ("name", "hook", "expected"), _CODEX_HOOKS, ids=[c[0] for c in _CODEX_HOOKS]
)
def test_codex_hook_calls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str, hook: _Hook, expected: _C
) -> None:
    classes = _classes(_ingest(tmp_path, monkeypatch, observe_hooks.handle_observe, hook))
    assert set(classes) == {expected}, (name, classes)


@pytest.mark.parametrize(
    ("name", "hook", "expected"), _CLAUDE_HOOKS, ids=[c[0] for c in _CLAUDE_HOOKS]
)
def test_claude_code_hook_calls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str, hook: _Hook, expected: _C
) -> None:
    classes = _classes(_ingest(tmp_path, monkeypatch, observe_hooks.handle_claude_observe, hook))
    assert set(classes) == {expected}, (name, classes)


@pytest.mark.parametrize(
    ("name", "hook", "expected"), _CURSOR_HOOKS, ids=[c[0] for c in _CURSOR_HOOKS]
)
def test_cursor_hook_calls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str, hook: _Hook, expected: _C
) -> None:
    classes = _classes(_ingest(tmp_path, monkeypatch, observe_hooks.handle_cursor_observe, hook))
    assert set(classes) == {expected}, (name, classes)


@pytest.mark.parametrize(
    ("description", "expected"),
    [
        ("Opaque observation kind=event_msg", _C.NO_TOOL_ACTIVITY),
        ("Opaque observation kind=response_item", _C.NO_TOOL_ACTIVITY),
        ("Opaque observation kind=token_usage_record", _C.NO_TOOL_ACTIVITY),
        ("Observed completion signal kind=Stop", _C.NO_TOOL_ACTIVITY),
        ("Observed completion signal kind=AgentMessage", _C.NO_TOOL_ACTIVITY),
        (
            "Routine-read summary observed calls=3 inputs=3 member_digest=x content_scope=none",
            _C.EXPLORATION,
        ),
        # A stream kind FinishUP does not know could carry anything: it stays disclosed.
        ("Opaque observation kind=brand_new_wrapper", _C.OTHER),
        ("Unpaired observed tool result exit=0", _C.OTHER),
        ("Observed post-only tool result", _C.OTHER),
        ("Observed host subagent start; origin=host_observed", _C.OTHER),
    ],
)
def test_stream_evidence_rows(description: str, expected: _C) -> None:
    """The evidence rows the materializer writes for items that name no tool call."""

    from finishup.domain.events import EvidenceKind
    from finishup.domain.values import evidence_id
    from finishup.protocol.coverage import EvidenceImmutability

    ledger = ObservedLedger()
    ledger.append(
        EventSchema("evidence_recorded", "1.0.0"),
        EvidenceRecordedPayload(
            evidence_id("evd_00000000-0000-4000-8000-000000000001"),
            EvidenceKind.OTHER,
            EvidenceImmutability.METADATA_ONLY,
            _RECEIPT,
            description=description,
        ),
        observed=True,
    )
    records = ledger.prefix
    assert classify_later_material(records[0], replay(records)).material_class is expected


def test_bare_stream_tool_name_is_finishup_own() -> None:
    """An ``McpToolCall`` item without a ``server`` names its tool alone (``status``)."""

    from finishup.domain.finishup_tools import finishup_tool_spelling

    assert finishup_tool_spelling("status") == "bare"
    assert finishup_tool_spelling("MCP:read_guidance") == "generic_mcp"
    assert finishup_tool_spelling("mcp__finishup__publish_work") == "server_scoped"
    assert (
        finishup_tool_spelling("mcp__plugin_finishup_finishup__closure_prepare") == "server_scoped"
    )
    assert finishup_tool_spelling("plugin-finishup-finishup:respond") == "server_prefixed"
    # Another server's tool, a longer name, or a non-string is never FinishUP's.
    for other in (
        "mcp__other__status",
        "status_check",
        "finishup:rm_rf",
        "MCP:statusx",
        "",
        7,
        None,
    ):
        assert finishup_tool_spelling(other) is None


def test_the_one_class_vocabulary() -> None:
    assert {member.value for member in LaterMaterialClass} == {
        "yoetz_own_call",
        "response",
        "exploration",
        "no_tool_activity",
        "non_counting_write",
        "edit_or_write",
        "other",
    }
    # Evidence of a result is classified by the call it answers, never cleaner than the call.
    assert AcceptedEvent  # imported for the type used by the helpers above


def test_every_spelling_the_delivery_policy_calls_finishup_owned_is_classified_finishup_own() -> (
    None
):
    """The delivery policy (#564) and the later-material rule read one meaning of "FinishUP's own".

    ``observation_local`` keeps its own prefix table; a spelling it adds without teaching
    ``domain.finishup_tools`` would be local-only there yet counted as later material here.
    """

    from finishup.adapters.integrations.observation_local import FINISHUP_OWNED_TOOL_NAMES
    from finishup.domain.finishup_tools import FINISHUP_MCP_TOOL_NAMES, finishup_tool_spelling

    assert FINISHUP_OWNED_TOOL_NAMES
    for name in sorted(FINISHUP_OWNED_TOOL_NAMES):
        assert finishup_tool_spelling(name) is not None, name
    # The support tool is advertised through MCP too (closure_prepare is read-only).
    assert "closure_prepare" in FINISHUP_MCP_TOOL_NAMES
    assert finishup_tool_spelling("mcp__finishup__closure_prepare") == "server_scoped"


# The spellings a 0.1-0.2.5 registration records (ADR-048), paired with the current spelling of
# the same call. Recorded observations keep the legacy names and replay reclassifies them, so each
# legacy hook must materialize and classify exactly as its current counterpart.
_LEGACY_SPELLINGS: tuple[tuple[str, Callable[[str], _Hook], str, str], ...] = (
    (
        "codex check",
        lambda tool: _codex(tool, "call_lc", {"mode": "deterministic_only"}, _OK),
        "mcp__finishup__check",
        "mcp__yoetz__check",
    ),
    (
        "codex status",
        lambda tool: _codex(tool, "call_ls", {"view": "findings"}, _OK),
        "mcp__finishup__status",
        "mcp__yoetz__status",
    ),
    (
        "claude check",
        lambda tool: _claude(tool, {}, "toolu_lc"),
        "mcp__plugin_finishup_finishup__check",
        "mcp__plugin_yoetz_yoetz__check",
    ),
    (
        "claude receipt",
        lambda tool: _claude(tool, {}, "toolu_lr"),
        "mcp__plugin_finishup_finishup__receipt",
        "mcp__plugin_yoetz_yoetz__receipt",
    ),
    (
        "cursor scoped status",
        lambda tool: _cursor(tool, {}, "cur_ls"),
        "finishup:status",
        "yoetz:status",
    ),
    (
        "cursor plugin-scoped check",
        lambda tool: _cursor(tool, {}, "cur_lc"),
        "plugin-finishup-finishup:check",
        "plugin-yoetz-yoetz:check",
    ),
)
_HANDLERS: dict[str, Callable[..., int]] = {
    "codex": observe_hooks.handle_observe,
    "claude": observe_hooks.handle_claude_observe,
    "cursor": observe_hooks.handle_cursor_observe,
}


@pytest.mark.parametrize(
    ("name", "hook", "current", "legacy"), _LEGACY_SPELLINGS, ids=[c[0] for c in _LEGACY_SPELLINGS]
)
def test_recorded_legacy_tool_names_classify_as_the_current_spelling_after_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    hook: Callable[[str], _Hook],
    current: str,
    legacy: str,
) -> None:
    handler = _HANDLERS[name.split(" ", 1)[0]]
    (tmp_path / "current").mkdir()
    (tmp_path / "legacy").mkdir()
    current_classes = _classes(_ingest(tmp_path / "current", monkeypatch, handler, hook(current)))
    legacy_classes = _classes(_ingest(tmp_path / "legacy", monkeypatch, handler, hook(legacy)))
    assert set(current_classes) == {_C.FINISHUP_OWN_CALL}, (name, current_classes)
    assert legacy_classes == current_classes, (name, legacy_classes)
