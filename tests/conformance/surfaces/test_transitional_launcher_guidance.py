"""Guidance tells agents what to run where only the deprecated ``yoetz`` launcher exists (ADR-048)."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Final

_REPO_ROOT: Final = Path(__file__).resolve().parents[3]


def _prose(relative: str) -> str:
    return re.sub(r"\s+", " ", (_REPO_ROOT / relative).read_text(encoding="utf-8"))


def test_workflow_names_the_alias_fallback_where_finishup_is_not_on_path() -> None:
    text = _prose("guidance/workflow.md")
    assert "`finishup` itself may not be on PATH" in text
    assert (
        "On such an install, where `finishup` is not found, run the same subcommand with "
        "`yoetz` for this release." in text
    )
    assert "A fresh install has only `finishup`." in text


def test_consent_review_runs_with_the_launcher_the_pending_names() -> None:
    text = _prose("guidance/consent.md")
    assert (
        "On an install upgraded through the transitional `yoetz` package, run these with the "
        "launcher the pending `review_command` names." in text
    )
