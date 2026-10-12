from __future__ import annotations

import hashlib
from dataclasses import replace

import pytest

from yoetz.domain.events import (
    ActionKind,
    ActionRecordedPayload,
    DecisionRecordedPayload,
    ObligationPublishedPayload,
    ObligationStatus,
    PlanPublishedPayload,
    RequestedItem,
    RequestedItemKind,
    encode_payload,
)
from yoetz.domain.values import EventId, action_id, actor_id, event_id, obligation_id
from yoetz.kernel.projections import (
    DecisionProjectionRecord,
    ObligationProjectionRecord,
    PlanProjectionRecord,
    ProjectionRecord,
    ProjectionState,
    empty_projection_state,
)
from yoetz.kernel.test_edit_visibility import preexisting_test_edits
from yoetz.ports.change_capture import (
    ChangeBaseKind,
    ChangeMetadataEntry,
    CheckChangeCapture,
    CheckChangeMetadata,
)
from yoetz.protocol.canonical import canonical_digest


def _projection(*, justified: bool) -> ProjectionState:
    action = ActionRecordedPayload(
        action_id=action_id("act_10000000-0000-4000-8000-000000000001"),
        action_kind=ActionKind.EDIT,
        description="Edit test",
        attempted_items=("tests/skip_test.py",),
    )
    action_record = ProjectionRecord(
        payload=action,
        payload_digest=canonical_digest(encode_payload(action)),
        redacted=False,
        source_event_id=event_id("evt_10000000-0000-4000-8000-000000000001"),
        source_frontier=1,
    )
    statement = (
        "yoetz:test-change:act_10000000-0000-4000-8000-000000000001:sha256:"
        + hashlib.sha256(b"tests/skip_test.py").hexdigest()
        if justified
        else "The test changed for a broader reason."
    )
    decision = DecisionRecordedPayload(
        statement=statement,
        rationale="Recorded test change.",
        authority=actor_id("human"),
    )
    decision_record = DecisionProjectionRecord(
        payload=decision,
        payload_digest=canonical_digest(encode_payload(decision)),
        redacted=False,
        source_event_id=event_id("evt_10000000-0000-4000-8000-000000000002"),
        source_frontier=2,
    )
    return replace(
        empty_projection_state(),
        frontier=2,
        head_digest="sha256:" + "a" * 64,
        actions={action.action_id: action_record},
        decisions={decision_record.source_event_id: decision_record},
    )


def _capture(
    base: ChangeBaseKind = "task_start", *, include_ordinary: bool = True
) -> CheckChangeCapture:
    ordinary_header = b"  M tests/ordinary_test.py (+1 -1)\n" if include_ordinary else b""
    ordinary_diff = (
        b"""diff --git a/tests/ordinary_test.py b/tests/ordinary_test.py
--- a/tests/ordinary_test.py
+++ b/tests/ordinary_test.py
@@ -1 +1 @@
-assert True
+assert False
"""
        if include_ordinary
        else b""
    )
    text = (
        b"""Yoetz check-time change
Files:
  M tests/skip_test.py (+1 -1)
"""
        + ordinary_header
        + b"""End of header. The unified diff follows.
diff --git a/tests/skip_test.py b/tests/skip_test.py
--- a/tests/skip_test.py
+++ b/tests/skip_test.py
@@ -1 +1 @@
-assert True
+pytest.skip(\"reason\")
"""
        + ordinary_diff
    )
    return CheckChangeCapture(
        base=base,
        text=text,
        tracked_files=2 if include_ordinary else 1,
        untracked_files=0,
        omitted_files=0,
        truncated=False,
        base_commit="a" * 40,
    )


def test_skip_marker_is_scoped_to_the_file_with_the_added_marker() -> None:
    facts = preexisting_test_edits(_capture())

    assert facts.modified == 2
    assert facts.skipped == 1
    assert facts.gaps == ("preexisting_test_modified", "preexisting_test_skipped")


def test_renamed_diff_uses_the_destination_path_for_skip_accounting() -> None:
    capture = CheckChangeCapture(
        base="task_start",
        text=b"""Yoetz check-time change
Files:
  R tests/new_test.py (+1 -1)
End of header. The unified diff follows.
diff --git a/tests/old_test.py b/tests/new_test.py
--- a/tests/old_test.py
+++ b/tests/new_test.py
@@ -1 +1 @@
-assert True
+pytest.skip("reason")
""",
        tracked_files=1,
        untracked_files=0,
        omitted_files=0,
        truncated=False,
        base_commit="a" * 40,
    )

    facts = preexisting_test_edits(capture)

    assert facts.renamed == 1
    assert facts.skipped == 1


def test_quoted_rename_header_decodes_destination_for_skip_accounting() -> None:
    capture = CheckChangeCapture(
        base="task_start",
        text=b"""Yoetz check-time change
Files:
  R "tests/new test.py" (+1 -1)
End of header. The unified diff follows.
diff --git "a/tests/old test.py" "b/tests/new test.py"
--- "a/tests/old test.py"
+++ "b/tests/new test.py"
@@ -1 +1 @@
-assert True
+pytest.skip("reason")
""",
        tracked_files=1,
        untracked_files=0,
        omitted_files=0,
        truncated=False,
        base_commit="a" * 40,
    )

    facts = preexisting_test_edits(capture)

    assert facts.renamed == 1
    assert facts.skipped == 1


def test_metadata_rename_keeps_original_test_path_in_structural_accounting() -> None:
    metadata = CheckChangeMetadata(
        base="task_start",
        entries=(
            ChangeMetadataEntry(
                "R",
                "src/new_helper.py",
                original_path="tests/old_test.py",
            ),
        ),
        tracked_files=1,
        untracked_files=0,
        omitted_files=0,
        truncated=False,
        base_commit="a" * 40,
    )

    facts = preexisting_test_edits(metadata)

    assert facts.renamed == 1
    assert facts.skipped == 0
    assert facts.unknown == 1
    # Path metadata reads the whole edit set but no diff body: only the skip marker is unknown,
    # so the baseline is known and the uncertainty has its own standing code (TB4 pilot).
    assert facts.skip_unknown == 1
    assert "preexisting_test_baseline_unknown" not in facts.gaps
    assert "preexisting_test_skip_unknown" in facts.gaps


def test_metadata_with_omitted_files_keeps_the_baseline_unknown() -> None:
    metadata = CheckChangeMetadata(
        base="task_start",
        entries=(ChangeMetadataEntry("M", "tests/skip_test.py"),),
        tracked_files=2,
        untracked_files=0,
        omitted_files=1,
        truncated=True,
        base_commit="a" * 40,
    )

    facts = preexisting_test_edits(metadata)

    assert facts.unknown == 2
    assert facts.skip_unknown == 1
    assert "preexisting_test_baseline_unknown" in facts.gaps
    assert "preexisting_test_skip_unknown" in facts.gaps


def test_js_skip_marker_and_unquoted_spaces_are_scoped_to_the_added_file() -> None:
    capture = CheckChangeCapture(
        base="task_start",
        text=b"""Yoetz check-time change
Files:
  M tests/foo b/test.js (+1 -1)
End of header. The unified diff follows.
diff --git a/tests/foo b/test.js b/tests/foo b/test.js
--- a/tests/foo b/test.js
+++ b/tests/foo b/test.js
@@ -1 +1 @@
-test("works", fn)
+it.skip("works", fn)
""",
        tracked_files=1,
        untracked_files=0,
        omitted_files=0,
        truncated=False,
        base_commit="a" * 40,
    )

    facts = preexisting_test_edits(capture)

    assert facts.modified == 1
    assert facts.skipped == 1


def test_truncated_task_start_capture_keeps_unknown_coverage_visible() -> None:
    capture = replace(_capture(include_ordinary=False), omitted_files=1, truncated=True)

    facts = preexisting_test_edits(capture)

    assert facts.modified == 1
    assert facts.unknown == 1
    assert "preexisting_test_baseline_unknown" in facts.gaps


def test_first_check_baseline_stays_explicitly_unknown() -> None:
    facts = preexisting_test_edits(_capture("first_check"))

    assert facts.any is False
    assert facts.baseline_known is False
    assert facts.gaps == ("preexisting_test_baseline_unknown",)


def test_generic_decision_does_not_clear_an_unjustified_edit() -> None:
    facts = preexisting_test_edits(_capture(include_ordinary=False), _projection(justified=False))

    assert facts.unjustified == 1
    assert "preexisting_test_edit_unjustified" in facts.gaps


def test_exact_action_and_path_marker_clears_the_edit_finding() -> None:
    facts = preexisting_test_edits(_capture(include_ordinary=False), _projection(justified=True))

    assert facts.unjustified == 0
    assert "preexisting_test_edit_unjustified" not in facts.gaps


def test_an_older_decision_does_not_clear_a_later_edit_of_the_same_path() -> None:
    projection = _projection(justified=True)
    newer = ActionRecordedPayload(
        action_id=action_id("act_10000000-0000-4000-8000-000000000002"),
        action_kind=ActionKind.EDIT,
        description="Edit test again",
        attempted_items=("tests/skip_test.py",),
    )
    newer_record = ProjectionRecord(
        payload=newer,
        payload_digest=canonical_digest(encode_payload(newer)),
        redacted=False,
        source_event_id=event_id("evt_10000000-0000-4000-8000-000000000003"),
        source_frontier=3,
    )
    projection = replace(
        projection,
        frontier=3,
        actions={**projection.actions, newer.action_id: newer_record},
    )

    facts = preexisting_test_edits(_capture(include_ordinary=False), projection)

    assert facts.unjustified == 1
    assert "preexisting_test_edit_unjustified" in facts.gaps


_STATEMENT_EVENT = event_id("evt_10000000-0000-4000-8000-000000000090")


def _with_statement_obligation(
    projection: ProjectionState,
    *,
    value: str,
    cites_statement: bool = True,
    item_kind: RequestedItemKind = RequestedItemKind.FILE,
) -> ProjectionState:
    """Add a plan whose one obligation requests ``value`` (TB4 mvcc pilot shape)."""

    obligation = ObligationPublishedPayload(
        obligation_id("obl_10000000-0000-4000-8000-000000000001"),
        "Add the requested regression test",
        "The regression test runs",
        ObligationStatus.OPEN,
        requested_items=(RequestedItem(item_kind, value),),
        source_refs=(_STATEMENT_EVENT,) if cites_statement else (),
    )
    plan = PlanPublishedPayload(1, "Plan", (obligation.obligation_id,))
    return replace(
        projection,
        plans={
            1: PlanProjectionRecord(
                payload=plan,
                payload_digest=canonical_digest(encode_payload(plan)),
                redacted=False,
                source_event_id=event_id("evt_10000000-0000-4000-8000-000000000091"),
                source_frontier=1,
            )
        },
        obligations={
            obligation.obligation_id: ObligationProjectionRecord(
                payload=obligation,
                payload_digest=canonical_digest(encode_payload(obligation)),
                redacted=False,
                source_event_id=event_id("evt_10000000-0000-4000-8000-000000000092"),
                source_frontier=1,
            )
        },
    )


@pytest.mark.parametrize(
    "value",
    ("tests/skip_test.py", "./tests/skip_test.py", "/app/tests/skip_test.py"),
)
def test_statement_sourced_obligation_requesting_the_file_justifies_the_edit(value: str) -> None:
    projection = _with_statement_obligation(_projection(justified=False), value=value)

    facts = preexisting_test_edits(
        _capture(include_ordinary=False), projection, task_statement_event_id=_STATEMENT_EVENT
    )

    assert facts.unjustified == 0
    assert "preexisting_test_edit_unjustified" not in facts.gaps
    # The edit stays visible as a disclosed pre-existing test modification.
    assert "preexisting_test_modified" in facts.gaps


@pytest.mark.parametrize(
    ("value", "cites", "kind", "statement"),
    (
        ("tests/skip_test.py", False, RequestedItemKind.FILE, _STATEMENT_EVENT),
        ("tests/skip_test.py", True, RequestedItemKind.CHANGE, _STATEMENT_EVENT),
        ("tests/other_test.py", True, RequestedItemKind.FILE, _STATEMENT_EVENT),
        ("app/tests/skip_test.py", True, RequestedItemKind.FILE, _STATEMENT_EVENT),
        ("tests/skip_test.py", True, RequestedItemKind.FILE, None),
    ),
)
def test_only_the_exact_statement_sourced_file_item_justifies_the_edit(
    value: str, cites: bool, kind: RequestedItemKind, statement: EventId | None
) -> None:
    projection = _with_statement_obligation(
        _projection(justified=False), value=value, cites_statement=cites, item_kind=kind
    )

    facts = preexisting_test_edits(
        _capture(include_ordinary=False), projection, task_statement_event_id=statement
    )

    assert facts.unjustified == 1
    assert "preexisting_test_edit_unjustified" in facts.gaps


def test_statement_sourced_file_item_also_justifies_a_metadata_only_edit() -> None:
    metadata = CheckChangeMetadata(
        base="task_start",
        entries=(ChangeMetadataEntry("M", "tests/skip_test.py"),),
        tracked_files=1,
        untracked_files=0,
        omitted_files=0,
        truncated=False,
        base_commit="a" * 40,
    )
    projection = _with_statement_obligation(
        _projection(justified=False), value="tests/skip_test.py"
    )

    justified = preexisting_test_edits(
        metadata, projection, task_statement_event_id=_STATEMENT_EVENT
    )
    assert justified.unjustified == 0
    assert preexisting_test_edits(metadata, projection).unjustified == 1


def test_an_obligation_citing_an_equivalent_statement_event_justifies_the_edit() -> None:
    """A re-attach that repeats the unchanged statement must not orphan the mapping (TB4 D2)."""

    projection = _with_statement_obligation(
        _projection(justified=False), value="tests/skip_test.py"
    )
    resumed = event_id("evt_10000000-0000-4000-8000-000000000099")

    equivalent = preexisting_test_edits(
        _capture(include_ordinary=False),
        projection,
        task_statement_event_id=(_STATEMENT_EVENT, resumed),
    )
    only_newer = preexisting_test_edits(
        _capture(include_ordinary=False), projection, task_statement_event_id=resumed
    )

    assert equivalent.unjustified == 0
    assert only_newer.unjustified == 1
