from __future__ import annotations

import hashlib
from dataclasses import replace

import pytest

from finishup.domain.events import (
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
from finishup.domain.values import EventId, action_id, actor_id, event_id, obligation_id
from finishup.kernel.projections import (
    DecisionProjectionRecord,
    ObligationProjectionRecord,
    PlanProjectionRecord,
    ProjectionRecord,
    ProjectionState,
    empty_projection_state,
)
from finishup.kernel.test_edit_visibility import preexisting_test_edits
from finishup.ports.change_capture import (
    ChangeBaseKind,
    ChangeMetadataEntry,
    CheckChangeCapture,
    CheckChangeMetadata,
)
from finishup.protocol.canonical import canonical_digest


def _projection(*, justified: bool, marker: str = "finishup:test-change") -> ProjectionState:
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
        f"{marker}:act_10000000-0000-4000-8000-000000000001:sha256:"
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
        b"""FinishUP check-time change
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
        text=b"""FinishUP check-time change
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
        text=b"""FinishUP check-time change
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
        text=b"""FinishUP check-time change
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


@pytest.mark.parametrize("marker", ("yoetz:test-change", "finishup:test-change"))
def test_the_marker_clears_the_edit_finding_under_either_spelling(marker: str) -> None:
    """ADR-048: decision statements recorded before the rename keep the ``yoetz`` spelling."""

    facts = preexisting_test_edits(
        _capture(include_ordinary=False), _projection(justified=True, marker=marker)
    )

    assert facts.unjustified == 0
    assert "preexisting_test_edit_unjustified" not in facts.gaps


@pytest.mark.parametrize(
    "marker", ("Yoetz:test-change", "yoetz-test-change", "finishup-test-change")
)
def test_no_other_spelling_of_the_marker_clears_the_edit_finding(marker: str) -> None:
    facts = preexisting_test_edits(
        _capture(include_ordinary=False), _projection(justified=True, marker=marker)
    )

    assert facts.unjustified == 1
    assert "preexisting_test_edit_unjustified" in facts.gaps


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


# Issue #1059: the dogfood shape. The request asked for edge-case tests and every host appended new
# test functions to the existing ``tests/test_spans.py``. The deterministic check reads only
# path/status metadata, so it cannot prove an edit append-only; these tests lock that it does not
# guess (append-only, modified and skip-marker edits stay unjustified until justified) and that the
# two justifications the finding names, spelled exactly as taught, clear it.
_SPANS = "tests/test_spans.py"
_SPANS_ACTION = action_id("act_10000000-0000-4000-8000-000000000059")
_SPANS_HEX = hashlib.sha256(_SPANS.encode("utf-8")).hexdigest()


def _spans_projection(decision_statement: str | None = None) -> ProjectionState:
    action = ActionRecordedPayload(
        action_id=_SPANS_ACTION,
        action_kind=ActionKind.EDIT,
        description="Add edge-case tests",
        attempted_items=(_SPANS,),
    )
    decisions: dict[EventId, DecisionProjectionRecord] = {}
    if decision_statement is not None:
        decision = DecisionRecordedPayload(
            statement=decision_statement,
            rationale="The request asked for new edge-case tests.",
            authority=actor_id("harness:test"),
        )
        record = DecisionProjectionRecord(
            payload=decision,
            payload_digest=canonical_digest(encode_payload(decision)),
            redacted=False,
            source_event_id=event_id("evt_10000000-0000-4000-8000-000000000061"),
            source_frontier=3,
        )
        decisions[record.source_event_id] = record
    return replace(
        empty_projection_state(),
        frontier=3,
        head_digest="sha256:" + "a" * 64,
        actions={
            action.action_id: ProjectionRecord(
                payload=action,
                payload_digest=canonical_digest(encode_payload(action)),
                redacted=False,
                source_event_id=event_id("evt_10000000-0000-4000-8000-000000000060"),
                source_frontier=2,
            )
        },
        decisions=decisions,
    )


def _spans_metadata() -> CheckChangeMetadata:
    return CheckChangeMetadata(
        base="task_start",
        entries=(ChangeMetadataEntry("M", _SPANS),),
        tracked_files=1,
        untracked_files=0,
        omitted_files=0,
        truncated=False,
        base_commit="a" * 40,
    )


_APPENDED_HUNK = b"""@@ -10,3 +10,7 @@ def test_merge_overlapping():
     assert merge([(1, 3), (2, 4)]) == [(1, 4)]
+
+
+def test_merge_empty_input():
+    assert merge([]) == []
"""
_MODIFIED_HUNK = b"""@@ -10,3 +10,3 @@ def test_merge_overlapping():
-    assert merge([(1, 3), (2, 4)]) == [(1, 4)]
+    assert merge([(1, 3), (2, 4)])
"""
_SKIP_ADDED_HUNK = (
    b"@@ -8,3 +8,4 @@ import pytest\n"
    b" \n"
    b'+@pytest.mark.skip(reason="flaky")\n'
    b" def test_merge_overlapping():\n"
    b"     assert merge([(1, 3), (2, 4)]) == [(1, 4)]\n"
)


def _spans_capture(hunk: bytes, counts: bytes) -> CheckChangeCapture:
    return CheckChangeCapture(
        base="task_start",
        text=b"FinishUP check-time change\nFiles:\n  M "
        + _SPANS.encode()
        + b" "
        + counts
        + b"\nEnd of header. The unified diff follows.\n"
        + b"diff --git a/tests/test_spans.py b/tests/test_spans.py\n"
        + b"--- a/tests/test_spans.py\n+++ b/tests/test_spans.py\n"
        + hunk,
        tracked_files=1,
        untracked_files=0,
        omitted_files=0,
        truncated=False,
        base_commit="a" * 40,
    )


def test_append_only_metadata_edit_is_still_an_unjustified_preexisting_test_edit() -> None:
    """Path/status metadata cannot tell an appended test from an edited one: fail closed."""

    facts = preexisting_test_edits(_spans_metadata(), _spans_projection())

    assert (facts.modified, facts.unjustified) == (1, 1)
    assert "preexisting_test_edit_unjustified" in facts.gaps
    assert facts.unjustified_action_event_ids == (
        event_id("evt_10000000-0000-4000-8000-000000000060"),
    )


@pytest.mark.parametrize(
    ("hunk", "counts", "skipped"),
    (
        (_APPENDED_HUNK, b"(+4 -0)", 0),
        (_MODIFIED_HUNK, b"(+1 -1)", 0),
        (_SKIP_ADDED_HUNK, b"(+1 -0)", 1),
    ),
    ids=("append_only", "modified_assertion", "skip_marker_added"),
)
def test_added_lines_alone_never_clear_a_preexisting_test_edit(
    hunk: bytes, counts: bytes, skipped: int
) -> None:
    """Added-only lines can still weaken a test (a skip decorator, an early return), so the
    kernel does not infer append-only from a diff body either; #973 stays protected."""

    facts = preexisting_test_edits(_spans_capture(hunk, counts), _spans_projection())

    assert (facts.modified, facts.skipped, facts.unjustified) == (1, skipped, 1)
    assert "preexisting_test_edit_unjustified" in facts.gaps
    assert ("preexisting_test_skipped" in facts.gaps) is bool(skipped)


@pytest.mark.parametrize("value", (_SPANS, f"./{_SPANS}", f"/work/{_SPANS}"))
def test_request_naming_the_test_file_justifies_the_appended_tests(value: str) -> None:
    projection = _with_statement_obligation(_spans_projection(), value=value)

    for capture in (_spans_metadata(), _spans_capture(_APPENDED_HUNK, b"(+4 -0)")):
        facts = preexisting_test_edits(
            capture, projection, task_statement_event_id=_STATEMENT_EVENT
        )
        assert facts.unjustified == 0
        assert "preexisting_test_edit_unjustified" not in facts.gaps
        # Still disclosed as an edit of a pre-existing test file.
        assert "preexisting_test_modified" in facts.gaps


def test_the_marker_line_the_finding_teaches_clears_the_edit() -> None:
    """The brief summary names the exact decision line; filled in, it clears the edit."""

    from finishup.kernel.deterministic_checks import TEST_EDIT_UNJUSTIFIED_SUMMARY
    from finishup.kernel.test_edit_visibility import TEST_CHANGE_MARKER

    assert f"{TEST_CHANGE_MARKER}:<act_ id of that edit action>:sha256:<the 64" in (
        TEST_EDIT_UNJUSTIFIED_SUMMARY
    )
    line = f"{TEST_CHANGE_MARKER}:{_SPANS_ACTION}:sha256:{_SPANS_HEX}"

    facts = preexisting_test_edits(_spans_metadata(), _spans_projection(f"Why.\n{line}\n"))

    assert facts.unjustified == 0
    assert "preexisting_test_edit_unjustified" not in facts.gaps


@pytest.mark.parametrize(
    "statement",
    (
        # The earlier guidance read literally: ``<path_digest>`` already carrying ``sha256:``.
        f"finishup:test-change:{_SPANS_ACTION}:sha256:sha256:{_SPANS_HEX}",
        # The digest of the absolute path, or of the bare file name.
        "finishup:test-change:{}:sha256:{}".format(
            _SPANS_ACTION, hashlib.sha256(b"/work/tests/test_spans.py").hexdigest()
        ),
        "finishup:test-change:{}:sha256:{}".format(
            _SPANS_ACTION, hashlib.sha256(b"test_spans.py").hexdigest()
        ),
        # The source event id instead of the act_ id.
        f"finishup:test-change:evt_10000000-0000-4000-8000-000000000060:sha256:{_SPANS_HEX}",
    ),
)
def test_a_misspelled_marker_line_does_not_clear_the_edit(statement: str) -> None:
    facts = preexisting_test_edits(_spans_metadata(), _spans_projection(statement))

    assert facts.unjustified == 1
