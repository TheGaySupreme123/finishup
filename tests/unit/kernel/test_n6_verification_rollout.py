"""The native completed CommandExecution remains the verifier when the agent polls stdin."""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

from builders.observed_runs import ObservedLedger
from finishup.adapters.integrations.codex_session_stream import SessionStreamReader
from finishup.adapters.integrations.observation_local import STREAM_MAPPING_VERSION
from finishup.application.observation_materialize import materialize_observation_envelope
from finishup.cli.observe_hooks import map_hook_payload_to_envelope
from finishup.domain.events import EventPayload, ResultOutcome, ResultRecordedPayload
from finishup.domain.observation import ObservationCursor
from finishup.domain.values import JsonObject
from finishup.kernel.reducers import replay
from finishup.kernel.task_facts import EDITED_AFTER_LAST_VERIFICATION_GAP, task_fact_signals
from fixture_loader import load_fixture_json


def test_write_stdin_completed_regression_verification_is_after_edit(tmp_path: Path) -> None:
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
        key_material=b"k" * 32,
    )
    observed = next(
        row for row in reader.advance(path).envelopes if row.event_kind == "item_completed"
    )
    assert observed.structural_payload["runner_class"] == "test"
    ledger = ObservedLedger()
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
        key_material=b"k" * 32,
    )
    for item in materialize_observation_envelope(
        poll, task_id=str(ledger.records[0].task_id)
    ).drafts:
        ledger.append(item.draft.schema, cast(EventPayload, item.draft.payload), observed=True)
    assert (
        EDITED_AFTER_LAST_VERIFICATION_GAP
        not in task_fact_signals(replay(ledger.prefix), ledger.prefix).codes
    )
    ledger.edit()
    assert (
        EDITED_AFTER_LAST_VERIFICATION_GAP
        in task_fact_signals(replay(ledger.prefix), ledger.prefix).codes
    )
