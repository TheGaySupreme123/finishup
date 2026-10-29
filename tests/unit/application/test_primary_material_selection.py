"""Primary narrowing keeps obligation and claim text (#1245, D22)."""

from __future__ import annotations

from finishup.application.semantic_case import primary_material_selection
from finishup.domain.privacy import ReviewSelectionPolicy


def _selection() -> ReviewSelectionPolicy:
    return ReviewSelectionPolicy(
        sections=(
            "claims",
            "decisions",
            "goal",
            "obligations",
            "targeted_excerpts",
            "timeline",
        ),
        excerpt_kinds=("diff",),
        relevance="linked_subjects_only",
        include_finding_prose=False,
        include_exact_command_text=False,
        max_timeline_items=4,
        max_assessments=4,
        max_change_observations=4,
        max_excerpts=4,
        max_omissions=4,
        max_excerpt_bytes=1024,
        max_total_excerpt_bytes=4096,
    )


def test_narrowing_keeps_obligations_and_claims_and_drops_goal() -> None:
    narrowed = primary_material_selection(_selection())
    assert "obligations" in narrowed.sections
    assert "claims" in narrowed.sections
    assert "decisions" in narrowed.sections
    assert "goal" not in narrowed.sections
    assert "timeline" not in narrowed.sections
