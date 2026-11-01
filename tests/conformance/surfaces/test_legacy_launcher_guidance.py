"""Guidance sends Yoetz-era commands to ``finishup``; no ``yoetz`` alias runs FinishUP (ADR-048)."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Final

_REPO_ROOT: Final = Path(__file__).resolve().parents[3]


def _prose(relative: str) -> str:
    return re.sub(r"\s+", " ", (_REPO_ROOT / relative).read_text(encoding="utf-8"))


def test_workflow_routes_yoetz_era_commands_to_finishup() -> None:
    text = _prose("guidance/workflow.md")
    assert "Run those commands as `finishup` with the same subcommand." in text
    assert (
        "A `yoetz` command still on PATH belongs to the earlier Yoetz release, not to FinishUP."
        in text
    )
    assert "transitional" not in text


def test_consent_review_runs_with_the_launcher_the_pending_names() -> None:
    text = _prose("guidance/consent.md")
    assert "Run these with the launcher the pending `review_command` names." in text
    assert "transitional" not in text
