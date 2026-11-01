"""Subagent hook lineage must not enter generic tool-call pairing (#607)."""

from __future__ import annotations

import io
import json
import uuid
from pathlib import Path

import pytest

from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.application.observation_materialize import materialize_observation_envelope
from finishup.cli.observe_hooks import handle_observe
from finishup.domain.observation import ObservationGapCode, ObservationStatusQuery
from finishup.protocol.ids import PREFIX_BY_KIND, IdKind


@pytest.mark.parametrize(
    "child_ids",
    (("child-one",), ("child-one", "child-two")),
    ids=("one-child", "two-children-sharing-parent"),
)
def test_subagent_roundtrips_do_not_use_parent_tool_pairing(
    tmp_path: Path, child_ids: tuple[str, ...]
) -> None:
    """Child start/stop lineage stays independent even when parent ids collide."""

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    parent_tool_call_id = "parent-tool-call-shared"

    for child_id in child_ids:
        for event_name in ("SubagentStart", "SubagentStop"):
            payload = {
                "session_id": "codex-child-roundtrip",
                "hook_event_name": event_name,
                "subagent_id": child_id,
                "parent_tool_call_id": parent_tool_call_id,
            }
            assert (
                handle_observe(
                    event_name=None,
                    stdin_bytes=json.dumps(payload).encode(),
                    stdout=io.BytesIO(),
                    workspace=str(tmp_path),
                    _state=tmp_path,
                    skip_service=True,
                )
                == 0
            )

    reopened = LocalObservationStore(_state=tmp_path)
    retained = reopened.list_envelopes(workspace)
    assert len(retained) == 2 * len(child_ids)
    assert {envelope.event_kind for envelope in retained} == {
        "SubagentStart",
        "SubagentStop",
    }
    assert all(
        ObservationGapCode.UNPAIRED_EVENT.value not in envelope.gap_codes for envelope in retained
    )
    assert (
        reopened.status(ObservationStatusQuery(workspace)).gaps.count(
            ObservationGapCode.UNPAIRED_EVENT.value
        )
        == 0
    )
    state = reopened._load(workspace)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    assert state.open_pre == {}

    task_id = PREFIX_BY_KIND[IdKind.TASK] + str(uuid.uuid4())
    batches = [materialize_observation_envelope(envelope, task_id=task_id) for envelope in retained]
    assert all(batch.skip_reason is None for batch in batches)
    assert all(ObservationGapCode.UNPAIRED_EVENT.value not in batch.gaps for batch in batches)
