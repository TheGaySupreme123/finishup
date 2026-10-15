"""Host tool-outcome contract tests driven by the OUT-001..OUT-003 payload fixtures (#910).

Every host adapter has, per tool-result event it consumes, at least one test driven by a recorded
or documented payload shape (``fixtures/observations/*-outcomes*.case.json``). The fixtures are
the contract: a payload is fed to the real hook handler exactly as the host delivers it, and the
closed outcome is read back from the local store and from ledger materialization. No test here
supplies a pre-normalized top-level ``exit_status``.
"""

from __future__ import annotations

import importlib.util
import io
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Final, cast

import pytest

from finishup.adapters.integrations.claude_code_integration import CLAUDE_CODE_ORDINARY_HOOK_EVENTS
from finishup.adapters.integrations.codex_session_stream import SessionStreamReader
from finishup.adapters.integrations.cursor_integration import CURSOR_ORDINARY_HOOK_EVENTS
from finishup.adapters.integrations.observation_local import (
    STREAM_MAPPING_VERSION,
    LocalObservationStore,
)
from finishup.application.observation_materialize import (
    HOST_OUTCOME_UNAVAILABLE_GAP,
    MaterializedObservationBatch,
    materialize_observation_envelope,
    materialize_observation_outcome_correction,
)
from finishup.cli.observe_hooks import (
    handle_claude_observe,
    handle_cursor_observe,
    handle_observe,
    map_hook_payload_to_envelope,
)
from finishup.domain.events import ResultOutcome, ResultRecordedPayload
from finishup.domain.observation import ObservationCursor, ObservationEnvelope, ObservationSource
from finishup.domain.observation_profiles import (
    CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
    CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
)
from finishup.protocol.canonical import JsonValue, canonical_encode
from fixture_loader import load_fixture_json

_CODEX: Final = "observations/codex-post-tool-outcomes-0.157.1.case.json"
_CLAUDE: Final = "observations/claude-code-bash-outcomes.case.json"
_CURSOR: Final = "observations/cursor-shell-outcomes.case.json"
_TASK: Final = "tsk_00000000-0000-4000-8000-000000000910"
_KEY: Final = b"k" * 32
_EMPTY: Final = "hmac-sha256:" + "0" * 64
_PLACEHOLDERS: Final = (b"PLACEHOLDER_OUTPUT", b"PLACEHOLDER_ERROR", b"PLACEHOLDER_COMMAND")
_TOOL_RESULT_EVENTS: Final = frozenset(
    {"PostToolUse", "PostToolUseFailure", "postToolUse", "postToolUseFailure"}
)


def _case(path: str) -> dict[str, Any]:
    return cast(dict[str, Any], load_fixture_json(path))


def _hook_variants(path: str) -> list[str]:
    return sorted(cast(dict[str, Any], _case(path)["input"]["hook"]))


def _result(batch: MaterializedObservationBatch) -> ResultRecordedPayload:
    results = [
        item.draft.payload
        for item in batch.drafts
        if type(item.draft.payload) is ResultRecordedPayload
    ]
    assert len(results) == 1, [item.role for item in batch.drafts]
    return results[0]


def _assert_outcome(
    envelope: ObservationEnvelope, expected: Mapping[str, Any]
) -> MaterializedObservationBatch:
    """Assert the persisted structural facts and the materialized ledger result."""

    structural = envelope.structural_payload
    assert structural.get("exit_status") == expected["exit_status"]
    assert structural.get("success") == expected["success"]
    assert structural.get("result_status") == expected["result_status"]
    batch = materialize_observation_envelope(envelope, task_id=_TASK)
    result = _result(batch)
    assert result.outcome is ResultOutcome(expected["outcome"])
    assert result.exit_status == expected["exit_status"]
    assert (HOST_OUTCOME_UNAVAILABLE_GAP in batch.coverage.known_gaps) is expected[
        "host_outcome_unavailable"
    ]
    return batch


def _state_bytes(state: Path) -> bytes:
    return b"".join(
        path.read_bytes() for path in state.rglob("*") if path.is_file() and not path.is_symlink()
    )


def _in_workspace(payload: Mapping[str, Any], root: Path) -> dict[str, Any]:
    """Point the fixture's placeholder project locator at this test's workspace."""

    encoded = json.dumps(payload).replace('"/workspace/project"', json.dumps(str(root.resolve())))
    return cast(dict[str, Any], json.loads(encoded))


def _pre_event(payload: Mapping[str, Any], event: str) -> dict[str, Any]:
    pre = {key: value for key, value in payload.items() if key != "tool_response"}
    pre["hook_event_name"] = event
    return pre


def _post_envelope(
    store: LocalObservationStore, workspace: str, call_id: str
) -> ObservationEnvelope:
    matches = [
        envelope
        for envelope in store.list_envelopes(workspace)
        if envelope.event_kind == "PostToolUse"
        and envelope.structural_payload.get("tool_call_id") == call_id
    ]
    assert len(matches) == 1, [item.structural_payload for item in store.list_envelopes(workspace)]
    return matches[0]


@pytest.mark.parametrize("variant", _hook_variants(_CODEX))
def test_codex_post_tool_use_fixture_records_the_stated_outcome(
    tmp_path: Path, variant: str
) -> None:
    """Each Codex 0.157.x PostToolUse shape keeps its closed outcome through the real handler."""

    case = _case(_CODEX)
    item = case["input"]["hook"][variant]
    expected = case["expected"]["hook"][variant]
    payload = cast(dict[str, Any], item["payload"])
    assert "exit_status" not in payload  # Codex never sends a top-level outcome.
    state = tmp_path / "state"
    store = LocalObservationStore(_state=state)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    for event, body in (
        ("PreToolUse", _pre_event(payload, "PreToolUse")),
        ("PostToolUse", payload),
    ):
        assert (
            handle_observe(
                event_name=event,
                stdin_bytes=canonical_encode(cast(JsonValue, body)),
                stdout=io.BytesIO(),
                workspace=str(tmp_path),
                _state=state,
                skip_service=True,
                source=ObservationSource.CODEX_HOOK,
            )
            == 0
        )

    envelope = _post_envelope(
        LocalObservationStore(_state=state), workspace, cast(str, payload["tool_use_id"])
    )
    assert "tool_response" not in envelope.structural_payload
    _assert_outcome(envelope, expected)
    persisted = _state_bytes(state)
    for placeholder in _PLACEHOLDERS:
        assert placeholder not in persisted


def test_codex_outcomes_leave_host_outcome_unavailable_only_on_outcome_less_records() -> None:
    """The standing gap names exactly the records whose host stated nothing, never the rest."""

    case = _case(_CODEX)
    session = "hmac-sha256:" + "c" * 64
    with_gap: set[str] = set()
    folded: set[str] = set()
    for ordinal, (variant, item) in enumerate(sorted(case["input"]["hook"].items()), start=1):
        envelope = map_hook_payload_to_envelope(
            "PostToolUse",
            cast(Mapping[str, JsonValue], item["payload"]),
            session_commitment=session,
            event_ordinal=ordinal,
            key_material=_KEY,
        )
        batch = _assert_outcome(envelope, case["expected"]["hook"][variant])
        if HOST_OUTCOME_UNAVAILABLE_GAP in batch.coverage.known_gaps:
            with_gap.add(variant)
        if item["provenance"] != "constructed_control":
            folded.update(batch.coverage.known_gaps)
    assert with_gap == {
        name for name, facts in case["expected"]["hook"].items() if facts["outcome"] == "unknown"
    }
    assert with_gap and all(
        case["input"]["hook"][name]["provenance"] == "constructed_control" for name in with_gap
    )
    # A session made only of the recorded shapes, every one with an outcome, folds no such gap.
    assert HOST_OUTCOME_UNAVAILABLE_GAP not in folded


@pytest.mark.parametrize(
    ("tool_name", "tool_response", "exit_status"),
    [
        ("exec_command", {"exit_code": 3, "output": "x"}, 3),
        ("shell", "Exit code: 0\nWall time: 1 seconds\nTotal output lines: 9\nOutput:\nx", 0),
        (
            "local_shell",
            "Chunk ID: ab\nWall time: 0.1 seconds\nProcess exited with code -1\n"
            "Original token count: 1\nOutput:\n",
            -1,
        ),
        ("Bash", '{"chunk_id":"c","wall_time_seconds":1.5,"exit_code":7,"output":"{}"}', 7),
    ],
)
def test_codex_command_tool_spellings_share_one_outcome_reader(
    tool_name: str, tool_response: JsonValue, exit_status: int
) -> None:
    envelope = map_hook_payload_to_envelope(
        "PostToolUse",
        {"tool_name": tool_name, "tool_use_id": "call-spelling", "tool_response": tool_response},
        session_commitment="hmac-sha256:" + "d" * 64,
        event_ordinal=1,
        key_material=_KEY,
    )
    assert envelope.structural_payload["exit_status"] == exit_status
    assert envelope.structural_payload["success"] is (exit_status == 0)


@pytest.mark.parametrize(
    "tool_response",
    [
        '{"exit_code": 1, "name": "package"}',  # a command's own JSON output, no exec-result key
        {"exit_code": 256},  # outside the closed -1..255 range
        {"exit_code": "1"},  # not an integer
        "Exit code: 0\nNot a header line\nOutput:\n",  # header grammar broken
        "Chunk ID: ab\nWall time: 1 seconds\nOriginal token count: 1\n",  # no Output terminator
        '{"chunk_id":"c","exit_code":null,"output":"x"}',  # still running
        "Output:\nExit code: 1\n",  # exit text inside the output, not the header
    ],
)
def test_codex_output_without_a_closed_exit_fact_stays_unknown(tool_response: JsonValue) -> None:
    envelope = map_hook_payload_to_envelope(
        "PostToolUse",
        {"tool_name": "Bash", "tool_use_id": "call-unknown", "tool_response": tool_response},
        session_commitment="hmac-sha256:" + "e" * 64,
        event_ordinal=1,
        key_material=_KEY,
    )
    assert "exit_status" not in envelope.structural_payload
    assert "success" not in envelope.structural_payload
    batch = materialize_observation_envelope(envelope, task_id=_TASK)
    assert _result(batch).outcome is ResultOutcome.UNKNOWN
    assert HOST_OUTCOME_UNAVAILABLE_GAP in batch.coverage.known_gaps


def test_codex_failed_read_is_not_summarized_as_a_routine_success() -> None:
    """Selection sees the nested failure, so a failed read never carries the routine marker."""

    session = "hmac-sha256:" + "f" * 64
    failed = map_hook_payload_to_envelope(
        "PostToolUse",
        {
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_use_id": "call-read-failed",
            "tool_input": {"command": "head missing.txt"},
            "tool_response": "Chunk ID: 1a\nWall time: 0.0100 seconds\nProcess exited with code 1\n"
            "Original token count: 9\nOutput:\nhead: missing.txt: No such file\n",
        },
        session_commitment=session,
        event_ordinal=1,
        key_material=_KEY,
    )
    assert failed.structural_payload.get("action") != "routine_read"
    assert failed.structural_payload["success"] is False
    assert failed.structural_payload["exit_status"] == 1
    succeeded = map_hook_payload_to_envelope(
        "PostToolUse",
        {
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_use_id": "call-read-ok",
            "tool_input": {"command": "head present.txt"},
            "tool_response": "Chunk ID: 1b\nWall time: 0.0100 seconds\nProcess exited with code 0\n"
            "Original token count: 9\nOutput:\ncontent\n",
        },
        session_commitment=session,
        event_ordinal=2,
        key_material=_KEY,
    )
    assert succeeded.structural_payload["action"] == "routine_read"
    assert succeeded.structural_payload["success"] is True
    assert succeeded.structural_payload["exit_status"] == 0


def test_masking_compound_shell_preserves_outer_zero_and_records_nested_gap() -> None:
    """A masking shell keeps its outer result while exposing the nested-status limitation (#968)."""

    envelope = map_hook_payload_to_envelope(
        "PostToolUse",
        {
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_use_id": "call-compound",
            "tool_input": {"command": "pnpm vitest test/a.ts; tsc --noEmit"},
            "tool_response": "Chunk ID: c\nWall time: 0.1 seconds\n"
            "Process exited with code 0\nOriginal token count: 1\nOutput:\n",
        },
        session_commitment="hmac-sha256:" + ("1a" * 32),
        event_ordinal=1,
        key_material=_KEY,
    )
    # ADR-045: a composition is classed by its strongest verification (the test run), while the
    # nested-status limitation stays raised for any masking shape.
    assert envelope.structural_payload["runner_class"] == "test"
    assert envelope.structural_payload["exit_status"] == 0
    assert envelope.structural_payload["success"] is True
    assert "compound_outcome_unavailable" in envelope.gap_codes
    result = _result(materialize_observation_envelope(envelope, task_id=_TASK))
    assert result.outcome is ResultOutcome.SUCCESS
    assert result.exit_status == 0


def test_and_compound_shell_zero_proves_each_chain_member() -> None:
    envelope = map_hook_payload_to_envelope(
        "PostToolUse",
        {
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_use_id": "call-compound-and",
            "tool_input": {"command": "pnpm vitest test/a.ts && tsc --noEmit"},
            "tool_response": "Chunk ID: c\nProcess exited with code 0\nOutput:\n",
        },
        session_commitment="hmac-sha256:" + ("1b" * 32),
        event_ordinal=1,
        key_material=_KEY,
    )
    assert (
        envelope.structural_payload["runner_class"] == "test"
    )  # ADR-045: classed by its strongest verification
    assert envelope.structural_payload["exit_status"] == 0
    assert "compound_outcome_unavailable" not in envelope.gap_codes


def test_runner_class_is_derived_instead_of_copied_from_host_payload() -> None:
    envelope = map_hook_payload_to_envelope(
        "PostToolUse",
        {
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_use_id": "call-runner-class",
            "runner_class": "exploration",
            "tool_input": {"command": "pytest tests/unit"},
            "tool_response": "Process exited with code 1",
        },
        session_commitment="hmac-sha256:" + ("1c" * 32),
        event_ordinal=1,
        key_material=_KEY,
    )
    assert envelope.structural_payload["runner_class"] == "test"


def _rollout_envelopes(tmp_path: Path, session: str) -> tuple[ObservationEnvelope, ...]:
    case = _case(_CODEX)
    lines = cast(list[dict[str, Any]], case["input"]["rollout"]["lines"])
    raw = b"".join(
        json.dumps(line, separators=(",", ":")).encode("utf-8") + b"\n" for line in lines
    )
    path = tmp_path / "rollout.jsonl"
    path.write_bytes(raw)
    reader = SessionStreamReader(
        session_commitment=session,
        profile=None,
        cursor=ObservationCursor(
            source_generation=1,
            byte_position=0,
            event_position=0,
            last_source_commitment=_EMPTY,
            mapping_version=STREAM_MAPPING_VERSION,
        ),
        key_material=_KEY,
    )
    advance = reader.advance(path)
    assert len(advance.envelopes) == len(lines)
    return advance.envelopes


def test_codex_rollout_completed_tool_items_record_their_outcome(tmp_path: Path) -> None:
    """``event_msg``/``item_completed`` command, MCP and patch items become results (#910)."""

    case = _case(_CODEX)
    expected = cast(list[dict[str, Any]], case["expected"]["rollout"])
    envelopes = _rollout_envelopes(tmp_path, "hmac-sha256:" + "a" * 64)
    for envelope, facts in zip(envelopes, expected, strict=True):
        assert envelope.event_kind == facts["event_kind"]
        if facts["event_kind"] != "item_completed":
            continue
        structural = envelope.structural_payload
        assert structural["tool_call_id"] == facts["tool_call_id"]
        assert structural["tool_name"] == facts["tool_name"]
        assert structural.get("exit_status") == facts["exit_status"]
        assert structural.get("result_status") == facts["result_status"]
        assert envelope.gap_codes == ()
        batch = materialize_observation_envelope(envelope, task_id=_TASK)
        assert tuple(item.role for item in batch.drafts) == ("action", "result")
        result = _result(batch)
        assert result.outcome is ResultOutcome(facts["outcome"])
        assert result.exit_status == facts["exit_status"]
        assert (HOST_OUTCOME_UNAVAILABLE_GAP in batch.coverage.known_gaps) is facts[
            "host_outcome_unavailable"
        ]
    dumped = json.dumps([dict(item.structural_payload) for item in envelopes]).encode()
    for placeholder in _PLACEHOLDERS:
        assert placeholder not in dumped


def test_codex_stream_failure_corrects_an_unknown_hook_result_when_ids_join(
    tmp_path: Path,
) -> None:
    """Where the hook call id equals the rollout item id, the stream fact corrects ``unknown``.

    Pairing a hook row with a stream row that carries a different id is #917's scope; this pins
    the minimum: an id join lets the explicit stream failure append a correction to the same
    canonical action without rewriting the hook's ``unknown`` row.
    """

    session = "hmac-sha256:" + "b" * 64
    stream = _rollout_envelopes(tmp_path, session)[1]
    call_id = cast(str, stream.structural_payload["tool_call_id"])
    hook = map_hook_payload_to_envelope(
        "PostToolUse",
        {
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_use_id": call_id,
            "tool_input": {"command": "PLACEHOLDER_COMMAND"},
            "tool_response": "Chunk ID: 9d\nWall time: 10.0 seconds\n"
            "Process running with session ID 4\nOriginal token count: 0\nOutput:\n",
        },
        session_commitment=session,
        event_ordinal=2,
        key_material=_KEY,
    )
    hook_batch = materialize_observation_envelope(hook, task_id=_TASK)
    stream_batch = materialize_observation_envelope(stream, task_id=_TASK)
    hook_result = _result(hook_batch)
    stream_result = _result(stream_batch)
    assert hook_result.outcome is ResultOutcome.UNKNOWN
    assert hook_result.result_id == stream_result.result_id
    assert stream_result.outcome is ResultOutcome.FAILURE

    correction = materialize_observation_outcome_correction(stream, task_id=_TASK)
    assert tuple(item.role for item in correction.drafts) == ("result_correction_failure_2",)
    corrected = cast(ResultRecordedPayload, correction.drafts[0].draft.payload)
    assert corrected.action_id == hook_result.action_id
    assert corrected.outcome is ResultOutcome.FAILURE
    assert corrected.exit_status == 2


@pytest.mark.parametrize("variant", _hook_variants(_CLAUDE))
def test_claude_code_bash_fixture_records_the_stated_outcome(tmp_path: Path, variant: str) -> None:
    case = _case(_CLAUDE)
    item = case["input"]["hook"][variant]
    payload = _in_workspace(cast(dict[str, Any], item["payload"]), tmp_path)
    state = tmp_path / "state"
    store = LocalObservationStore(_state=state)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    for event, body in (
        ("PreToolUse", _pre_event(payload, "PreToolUse")),
        (item["event"], payload),
    ):
        assert (
            handle_claude_observe(
                event_name=event,
                stdin_bytes=canonical_encode(cast(JsonValue, body)),
                stdout=io.BytesIO(),
                workspace=str(tmp_path),
                _state=state,
                skip_service=True,
                observation_profile=CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
            )
            == 0
        )
    envelope = _post_envelope(
        LocalObservationStore(_state=state), workspace, cast(str, payload["tool_use_id"])
    )
    _assert_outcome(envelope, case["expected"]["hook"][variant])
    persisted = _state_bytes(state)
    for placeholder in _PLACEHOLDERS:
        assert placeholder not in persisted


@pytest.mark.parametrize("variant", _hook_variants(_CURSOR))
def test_cursor_shell_fixture_records_the_stated_outcome(tmp_path: Path, variant: str) -> None:
    case = _case(_CURSOR)
    item = case["input"]["hook"][variant]
    payload = _in_workspace(cast(dict[str, Any], item["payload"]), tmp_path)
    state = tmp_path / "state"
    store = LocalObservationStore(_state=state)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    for event, body in (
        ("preToolUse", _pre_event(payload, "preToolUse")),
        (item["event"], payload),
    ):
        assert (
            handle_cursor_observe(
                event_name=event,
                stdin_bytes=canonical_encode(cast(JsonValue, body)),
                stdout=io.BytesIO(),
                workspace=str(tmp_path),
                _state=state,
                skip_service=True,
                observation_profile=CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
            )
            == 0
        )
    envelope = _post_envelope(
        LocalObservationStore(_state=state), workspace, cast(str, payload["tool_use_id"])
    )
    _assert_outcome(envelope, case["expected"]["hook"][variant])
    persisted = _state_bytes(state)
    for placeholder in _PLACEHOLDERS:
        assert placeholder not in persisted


@pytest.mark.parametrize(
    ("path", "consumed"),
    [
        (_CODEX, frozenset({"PostToolUse"})),
        (_CLAUDE, frozenset(CLAUDE_CODE_ORDINARY_HOOK_EVENTS) & _TOOL_RESULT_EVENTS),
        (_CURSOR, frozenset(CURSOR_ORDINARY_HOOK_EVENTS) & _TOOL_RESULT_EVENTS),
    ],
)
def test_every_consumed_tool_result_event_has_a_payload_fixture(
    path: str, consumed: frozenset[str]
) -> None:
    """Standing contract rule (#910): a consumed tool-result event needs a payload fixture.

    Adding a tool-result event to a host profile without a fixture variant for it fails here.
    Each case also states where its shapes came from and whether raw hook stdin was captured,
    so a derived shape is never presented as a capture.
    """

    case = _case(path)
    covered = {item["event"] for item in case["input"]["hook"].values()}
    assert consumed and consumed <= covered
    provenance = case["provenance"]
    assert provenance["capture"] in {
        "captured_raw_hook_stdin",
        "derived_from_documented_host_shape",
        "derived_from_recorded_rollout",
    }
    assert provenance["raw_hook_stdin_capture"] in {"captured", "pending"}
    assert "raw hook stdin capture" in provenance["statement"]
    for item in case["input"]["hook"].values():
        assert item["provenance"] in {provenance["capture"], "constructed_control"}


def test_host_outcome_fixtures_are_owned_by_their_generator() -> None:
    root = Path(__file__).resolve().parents[3]
    spec = importlib.util.spec_from_file_location(
        "generate_host_outcome_fixtures", root / "scripts" / "generate_host_outcome_fixtures.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    files, manifest = cast(tuple[dict[Path, bytes], bytes], module._expected(root))
    for path, data in files.items():
        assert path.read_bytes() == data, path
    assert (root / "fixtures" / "manifest.json").read_bytes() == manifest


@pytest.mark.parametrize(
    ("tool_response", "success", "exit_status"),
    [
        ({"exit_code": 0, "is_error": True}, False, None),  # a stated error wins over exit 0
        ({"exit_code": 0, "isError": False}, True, 0),
        ({"isError": False, "output": "x"}, None, None),  # an error bit is not a process exit
    ],
)
def test_codex_command_error_bit_only_ever_fails_a_result(
    tool_response: JsonValue, success: bool | None, exit_status: int | None
) -> None:
    envelope = map_hook_payload_to_envelope(
        "PostToolUse",
        {"tool_name": "Bash", "tool_use_id": "call-error-bit", "tool_response": tool_response},
        session_commitment="hmac-sha256:" + "9" * 64,
        event_ordinal=1,
        key_material=_KEY,
    )
    assert envelope.structural_payload.get("success") is success
    assert envelope.structural_payload.get("exit_status") == exit_status


def _advice_unresolved(envelopes: tuple[ObservationEnvelope, ...]) -> list[tuple[str, ...]]:
    from finishup.domain.observation import ObservationLifecycle
    from finishup.kernel.policies.observation_advice import (
        ObservationAdviceContext,
        observation_advice_findings,
    )

    return [
        item.evidence_refs
        for item in observation_advice_findings(
            ObservationAdviceContext(
                envelopes=envelopes, lifecycle=ObservationLifecycle.ACTIVE, gaps=()
            )
        )
        if item.rule_code == "failed_command_unresolved"
    ]


@pytest.mark.parametrize("tool_name", ["Bash", "exec_command", "local_shell"])
def test_codex_shell_failure_reaches_the_unresolved_command_advice(tool_name: str) -> None:
    """Every Codex shell spelling is a command the advice reads; a rerun clears it (#909)."""

    session = "hmac-sha256:" + "8" * 64
    argument = "command" if tool_name == "Bash" else "cmd"

    def run(ordinal: int, call: str, exit_code: int) -> ObservationEnvelope:
        return map_hook_payload_to_envelope(
            "PostToolUse",
            {
                "hook_event_name": "PostToolUse",
                "tool_name": tool_name,
                "tool_use_id": call,
                "tool_input": {argument: "npm run test-type"},
                "tool_response": "Chunk ID: 4b\nWall time: 2.5 seconds\n"
                f"Process exited with code {exit_code}\nOriginal token count: 7\nOutput:\n",
            },
            session_commitment=session,
            event_ordinal=ordinal,
            key_material=_KEY,
        )

    red = run(1, "call-red", 2)
    assert (
        red.structural_payload["command_commitment"]
        == run(9, "x", 0).structural_payload["command_commitment"]
    )
    assert len(_advice_unresolved((red,))) == 1
    assert _advice_unresolved((red, run(2, "call-green", 0))) == []


def test_codex_stream_copy_of_a_command_is_not_a_second_advice_subject(tmp_path: Path) -> None:
    """Until #917 pairs hook and stream copies, only the hook copy drives the advice."""

    session = "hmac-sha256:" + "7" * 64
    stream = _rollout_envelopes(tmp_path, session)[1]
    assert stream.structural_payload["tool_name"] == "command_execution"
    assert _advice_unresolved((stream,)) == []


@pytest.mark.parametrize(
    ("tool_name", "tool_response"),
    [
        # A code-mode ``exec`` cell's result is model-authored JSON, never a process exit.
        ("exec", '{"chunk_id":"c","exit_code":1,"output":"x"}'),
        ("exec", {"exit_code": 1}),
        # JSON text needs an exec-result key and a string ``output`` to be the host's result.
        ("Bash", '{"chunk_id":"c","exit_code":1}'),
        ("Bash", '{"chunk_id":"c","exit_code":1,"output":null}'),
    ],
)
def test_codex_reader_ignores_cells_and_incomplete_exec_results(
    tool_name: str, tool_response: JsonValue
) -> None:
    envelope = map_hook_payload_to_envelope(
        "PostToolUse",
        {"tool_name": tool_name, "tool_use_id": "call-cell", "tool_response": tool_response},
        session_commitment="hmac-sha256:" + "6" * 64,
        event_ordinal=1,
        key_material=_KEY,
    )
    assert "exit_status" not in envelope.structural_payload
    assert "success" not in envelope.structural_payload


@pytest.mark.parametrize(
    ("item", "outcome"),
    [
        ({"status": "completed"}, ResultOutcome.SUCCESS),
        ({"status": "completed", "error": {"message": "x"}}, ResultOutcome.FAILURE),
        (
            {"status": "completed", "result": {"content": [], "isError": True}},
            ResultOutcome.FAILURE,
        ),
        (
            {"status": "completed", "result": {"content": [], "isError": False}},
            ResultOutcome.SUCCESS,
        ),
    ],
)
def test_codex_stream_mcp_item_failure_wins(
    tmp_path: Path, item: dict[str, JsonValue], outcome: ResultOutcome
) -> None:
    from builders.codex_rollout import encode_lines, item_completed, session_meta

    path = tmp_path / "rollout.jsonl"
    path.write_bytes(
        encode_lines(
            session_meta(cli_version="0.157.1", history_mode="paginated"),
            item_completed(
                {
                    "arguments": {},
                    "id": "call_910_mcp_item",
                    "server": "finishup",
                    "tool": "publish_work",
                    "type": "McpToolCall",
                    **item,
                }
            ),
        )
    )
    reader = SessionStreamReader(
        session_commitment="hmac-sha256:" + "4" * 64,
        profile=None,
        cursor=ObservationCursor(
            source_generation=1,
            byte_position=0,
            event_position=0,
            last_source_commitment=_EMPTY,
            mapping_version=STREAM_MAPPING_VERSION,
        ),
        key_material=_KEY,
    )
    envelope = reader.advance(path).envelopes[-1]
    assert envelope.event_kind == "item_completed"
    assert _result(materialize_observation_envelope(envelope, task_id=_TASK)).outcome is outcome
