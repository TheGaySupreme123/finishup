"""#1245 (D22): the narrowing record reads the case's effective selection, not only planning."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

import finishup.observability.diagnostics as diagnostics_module
from finishup.service.ready_composition import (
    _record_case_narrowing,  # pyright: ignore[reportPrivateUsage]
)


def _records(tmp_path: Path) -> list[Mapping[str, object]]:
    path = diagnostics_module.diagnostic_log_path(root=tmp_path)
    if not path.exists():
        return []
    return [
        cast(Mapping[str, object], json.loads(line))
        for line in path.read_text(encoding="ascii").splitlines()
        if line
    ]


def _case(sections: frozenset[str]) -> Any:
    return SimpleNamespace(
        review_selection=SimpleNamespace(sections=sections),
        packet=SimpleNamespace(
            obligation_item_ids=("obligation-1", "obligation-2"), claim_item_ids=("claim-1",)
        ),
    )


_APPROVED = SimpleNamespace(sections=frozenset({"goal", "obligations", "claims", "timeline"}))


def test_a_builder_narrowing_without_a_planning_round_is_recorded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(diagnostics_module, "log_dir", lambda: tmp_path)
    case = _case(frozenset({"obligations", "claims", "timeline"}))
    _record_case_narrowing("req-1", 0, cast(Any, _APPROVED), case)
    [row] = [row for row in _records(tmp_path) if row["operation"] == "semantic_case_narrowed"]
    assert row["semantic_section_dropped_goal"] == 1
    assert row["semantic_section_dropped_obligations"] == 0
    assert row["semantic_section_dropped_claims"] == 0
    assert row["semantic_excerpt_ceiling_rounds"] == 0
    assert row["semantic_obligation_rows_selected"] == 2
    assert row["semantic_claim_rows_selected"] == 1


def test_an_unnarrowed_case_writes_no_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(diagnostics_module, "log_dir", lambda: tmp_path)
    _record_case_narrowing("req-2", 0, cast(Any, _APPROVED), _case(_APPROVED.sections))
    assert not [row for row in _records(tmp_path) if row["operation"] == "semantic_case_narrowed"]
