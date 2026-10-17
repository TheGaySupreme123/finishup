"""The native completed CommandExecution remains the verifier when the agent polls stdin."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import cast

import pytest

from builders.observed_runs import INSTALLATION_KEY, ObservedLedger
from finishup.adapters.integrations.codex_session_stream import SessionStreamReader
from finishup.adapters.integrations.observation_local import STREAM_MAPPING_VERSION
from finishup.application.observation_materialize import materialize_observation_envelope
from finishup.cli.observe_hooks import map_hook_payload_to_envelope
from finishup.domain.events import EventPayload, ResultOutcome, ResultRecordedPayload
from finishup.domain.observation import ObservationCursor
from finishup.domain.values import JsonObject
from finishup.kernel.reducers import replay
from finishup.kernel.task_facts import (
    EDITED_AFTER_LAST_VERIFICATION_GAP,
    register_command_identity_key,
    task_fact_signals,
)
from fixture_loader import load_fixture_json
from unit.kernel.test_n6_closing_review_delta import declare_verifier


@pytest.fixture(autouse=True)
def installation_key() -> Iterator[None]:
    register_command_identity_key(INSTALLATION_KEY)
    yield
    register_command_identity_key(None)


@pytest.mark.parametrize(
    "command,exploration",
    [
        (["/bin/bash", "-lc", "date -u"], True),
        (["/shadow/bin/bash", "-lc", "date -u; date -u"], False),
        (["/bin/bash", "-lc", "/shadow/bin/bash -c 'date -u; date -u'"], False),
        (["/bin/bash", "-lc", "env PATH=/shadow date -u"], False),
    ],
)
def test_native_read_identity_keeps_executable_paths(
    tmp_path: Path, command: list[str], exploration: bool
) -> None:
    fixture = cast(
        dict[str, object],
        load_fixture_json("observations/codex-post-tool-outcomes-0.157.1.case.json"),
    )
    rollout = cast(dict[str, object], cast(dict[str, object], fixture["input"])["rollout"])
    lines = json.loads(json.dumps(rollout["lines"]))
    lines[2]["payload"]["item"].update(command=command, id="call-read-provenance")
    path = tmp_path / "rollout.jsonl"
    path.write_text("".join(json.dumps(line) + "\n" for line in [lines[0], lines[2]]))
    reader = SessionStreamReader(
        session_commitment="hmac-sha256:" + "1" * 64,
        profile=None,
        cursor=ObservationCursor(1, 0, 0, "hmac-sha256:" + "0" * 64, STREAM_MAPPING_VERSION),
        key_material=INSTALLATION_KEY,
    )
    observed = next(
        row for row in reader.advance(path).envelopes if row.event_kind == "item_completed"
    )
    assert (observed.structural_payload["runner_class"] == "exploration") is exploration


@pytest.mark.parametrize("declared", [False, True])
def test_write_stdin_completed_regression_verification_is_after_edit(
    tmp_path: Path, declared: bool
) -> None:
    # Bounded reduction of the vLLM audited command: verifier scripts, heredoc, log and date.
    command = """set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1
{
python -B /tmp/deepseek_stream_regression.py
python -B /tmp/deepseek_finalizer_regression.py
python -B - <<'PYCODE'
import ast
ast.parse('answer = 42')
PYCODE
} | tee /tmp/deepseek_final_validation.log
date -u
"""
    fixture = cast(
        dict[str, object],
        load_fixture_json("observations/codex-post-tool-outcomes-0.157.1.case.json"),
    )
    rollout = cast(dict[str, object], cast(dict[str, object], fixture["input"])["rollout"])
    lines = json.loads(json.dumps(rollout["lines"]))
    completed = lines[2]
    completed["payload"]["item"].update(
        command=["/bin/bash", "-lc", command],
        id="call-verifier",
        process_id="45430",
        stdout="Fuzz cases: 1000; passed: 1000; failed: 0",
    )
    path = tmp_path / "rollout.jsonl"
    path.write_text("".join(json.dumps(line) + "\n" for line in [lines[0], completed]))
    session = "hmac-sha256:" + "1" * 64
    reader = SessionStreamReader(
        session_commitment=session,
        profile=None,
        cursor=ObservationCursor(1, 0, 0, "hmac-sha256:" + "0" * 64, STREAM_MAPPING_VERSION),
        key_material=INSTALLATION_KEY,
    )
    observed = next(
        row for row in reader.advance(path).envelopes if row.event_kind == "item_completed"
    )
    assert observed.structural_payload["runner_class"] == "compound"
    ledger = ObservedLedger()
    if declared:
        declare_verifier(ledger, "python -B /tmp/deepseek_stream_regression.py")
    ledger.passes("npm run build")
    ledger.edit()
    batch = materialize_observation_envelope(observed, task_id=str(ledger.records[0].task_id))
    for item in batch.drafts:
        ledger.append(item.draft.schema, cast(EventPayload, item.draft.payload), observed=True)
    completed_result = next(
        item.draft.payload
        for item in batch.drafts
        if type(item.draft.payload) is ResultRecordedPayload
    )
    assert completed_result.outcome is ResultOutcome.SUCCESS
    poll = map_hook_payload_to_envelope(
        "PostToolUse",
        JsonObject(
            {
                "tool_name": "write_stdin",
                "tool_use_id": "call-poll",
                "tool_input": {"session_id": 45430, "chars": ""},
                "tool_response": "Chunk ID: 329e51\nWall time: 0.0000 seconds\n"
                "Process exited with code 0\nOutput:\n1000 passed\n",
            }
        ),
        session_commitment=session,
        event_ordinal=2,
        key_material=INSTALLATION_KEY,
    )
    for item in materialize_observation_envelope(
        poll, task_id=str(ledger.records[0].task_id)
    ).drafts:
        ledger.append(item.draft.schema, cast(EventPayload, item.draft.payload), observed=True)
    assert (
        EDITED_AFTER_LAST_VERIFICATION_GAP
        in task_fact_signals(replay(ledger.prefix), ledger.prefix).codes
    ) is not declared
    ledger.edit()
    assert (
        EDITED_AFTER_LAST_VERIFICATION_GAP
        in task_fact_signals(replay(ledger.prefix), ledger.prefix).codes
    )
