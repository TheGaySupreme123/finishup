"""Compatibility coverage for retained observation provenance versions 11 through 13."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.domain.observation import (
    ObservationCursor,
    ObservationEnvelope,
    ObservationGapCode,
    ObservationIngestDisposition,
    ObservationSource,
    ObservationStatusQuery,
)
from finishup.domain.values import JsonObject, Timestamp

_UNPAIRED = ObservationGapCode.UNPAIRED_EVENT.value
_TRUNCATED = ObservationGapCode.TRUNCATED_PAYLOAD.value
_STAMP = Timestamp("2026-01-01T00:00:00.000Z")


def _seed_historical_post_only(tmp_path: Path) -> tuple[LocalObservationStore, str, Path]:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    store = LocalObservationStore(_state=state)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace, _STAMP)
    session = store.session_commitment("claude-provenance-version")
    envelope = ObservationEnvelope(
        session_commitment=session,
        event_kind="PostToolUse",
        source_identity="claude:historical-post-only",
        source=ObservationSource.CLAUDE_HOOK,
        cursor=ObservationCursor(
            1,
            0,
            1,
            "hmac-sha256:" + "ab" * 32,
            "codex-obs-hook/1.0.0",
        ),
        receipt_time=_STAMP,
        structural_payload=JsonObject(
            {
                "capability_profile_id": "claude-code-cli-local-project-2.1.241",
                "correlation_kind": "tool_call_id",
                "mapping_hint": "claude-code-hooks-ordinary-v1",
                "pairing_mode": "post_only",
                "tool_call_id": "historical-call",
                "tool_name": "shell",
            }
        ),
        content_object_refs=(),
        gap_codes=(_UNPAIRED,),
    )
    result = store.ingest(envelope, workspace_commitment=workspace)
    assert result.disposition is ObservationIngestDisposition.ACCEPTED
    state_path = next((state / "observation" / "workspaces").glob("*.json"))
    return store, workspace, state_path


def _rewrite_version(
    state_path: Path,
    *,
    version: int,
    true_orphan: bool,
    include_truncation_history: bool,
) -> None:
    raw = json.loads(state_path.read_text(encoding="utf-8"))
    # Frozen legacy identifier (ADR-048): the persisted observation-local state tag.
    raw["schema"] = f"yoetz.observation-local/{version}"
    raw["pairing_state_unknown"] = False
    raw.pop("envelopes_truncated", None)
    if version < 13:
        raw.pop("content_capture_epoch", None)
    raw["unpaired_scopes"] = ["true-orphan"] if true_orphan else []
    raw["gaps"] = [_UNPAIRED]
    raw["gap_history"][_UNPAIRED]["active"] = True
    if include_truncation_history:
        raw["gaps"].append(_TRUNCATED)
        raw["gap_history"][_TRUNCATED] = {
            "active": True,
            "first_seen": _STAMP.wire,
            "last_seen": _STAMP.wire,
        }
    state_path.write_text(json.dumps(raw), encoding="utf-8")


@pytest.mark.parametrize("version", (11, 12, 13))
def test_known_provenance_versions_retire_post_only_false_positive_without_inferred_truncation(
    tmp_path: Path, version: int
) -> None:
    _store, workspace, state_path = _seed_historical_post_only(tmp_path)
    _rewrite_version(
        state_path,
        version=version,
        true_orphan=False,
        include_truncation_history=True,
    )

    reopened = LocalObservationStore(_state=tmp_path / "state")
    status = reopened.status(ObservationStatusQuery(workspace))

    assert _UNPAIRED not in status.gaps
    persisted = json.loads(state_path.read_text(encoding="utf-8"))
    assert persisted["gap_history"][_UNPAIRED]["active"] is False
    assert persisted["gap_history"][_TRUNCATED]["active"] is False
    assert _TRUNCATED in persisted["gaps"]
    assert persisted.get("envelopes_truncated") is None


@pytest.mark.parametrize("version", (11, 12, 13))
def test_known_provenance_versions_preserve_true_orphan_gap(tmp_path: Path, version: int) -> None:
    _store, workspace, state_path = _seed_historical_post_only(tmp_path)
    _rewrite_version(
        state_path,
        version=version,
        true_orphan=True,
        include_truncation_history=False,
    )

    reopened = LocalObservationStore(_state=tmp_path / "state")
    status = reopened.status(ObservationStatusQuery(workspace))

    assert _UNPAIRED in status.gaps
    persisted = json.loads(state_path.read_text(encoding="utf-8"))
    assert persisted["gap_history"][_UNPAIRED]["active"] is True
