"""ADR-051 decision 5: what listed mode kept back reaches the diagnostics beside the case record.

``semantic_case_built`` is at the 1,024-byte diagnostic line bound, and a line over it is dropped
whole. The count of files a remote server's workspace agent kept back under its owner's listed
mode therefore has its own ``semantic_case_outside_not_listed`` record under the same request id,
written only when not zero, and the case-built record keeps reaching the durable ring.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import cast

import pytest

import finishup.observability.diagnostics as diagnostics_module
from finishup.service.ready_composition import (
    _record_case_built,  # pyright: ignore[reportPrivateUsage]
)

_REQUEST = "req_53000000-0000-4000-8000-000000000001"
# The widest case-built record the semantic tests produce: every counter present, the excerpt
# counters at their large expanded-profile values.
_BUILT: Mapping[str, int] = {
    "semantic_capture_parts_resolved": 0,
    "semantic_diff_parts_resolved": 0,
    "semantic_excerpts_selected": 16,
    "semantic_diff_excerpts_selected": 0,
    "semantic_excerpt_bytes_selected": 128_000,
    "semantic_excerpt_count_approved": 64,
    "semantic_excerpt_byte_approved": 131_072,
    "semantic_excerpt_count_limit": 64,
    "semantic_excerpt_count_cut_for_case_bound": 0,
    "semantic_excerpt_byte_limit": 131_072,
    "semantic_excerpt_ceiling_rounds": 0,
    "semantic_first_exchange_frame_unplanned": 0,
    "semantic_check_change_parts_selected": 0,
    "semantic_edit_evidence_in_case": 0,
    "semantic_task_input_candidates": 0,
    "semantic_task_input_excerpts_selected": 0,
    "semantic_task_input_listings": 0,
    "semantic_task_input_outside_candidates": 0,
    "semantic_task_inputs_outside_not_admitted": 0,
    "semantic_task_inputs_read": 0,
}


def _records(tmp_path: Path) -> list[Mapping[str, object]]:
    path = diagnostics_module.diagnostic_log_path(root=tmp_path)
    if not path.exists():
        return []
    return [
        cast(Mapping[str, object], json.loads(line))
        for line in path.read_text(encoding="ascii").splitlines()
        if line
    ]


def test_files_listed_mode_kept_back_have_their_own_record_beside_the_case(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(diagnostics_module, "log_dir", lambda: tmp_path)

    _record_case_built(_REQUEST, 3, _BUILT)

    built, kept_back = _records(tmp_path)
    assert built["operation"] == "semantic_case_built"
    assert built["semantic_excerpt_byte_limit"] == 131_072
    assert "semantic_task_inputs_outside_not_listed" not in built
    assert kept_back["operation"] == "semantic_case_outside_not_listed"
    assert kept_back["request_id"] == built["request_id"] == _REQUEST
    assert kept_back["semantic_task_inputs_outside_not_listed"] == 3


def test_nothing_kept_back_writes_only_the_case_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(diagnostics_module, "log_dir", lambda: tmp_path)

    _record_case_built(_REQUEST, 0, _BUILT)

    [built] = _records(tmp_path)
    assert built["operation"] == "semantic_case_built"
