"""Packet completeness within the existing budget (issue #1045, tb4n4).

Each case is built from the shape the tb4n4 review exports describe: a read-only input the task
statement names (vba-userform-port), a probe re-run whose newest output was never captured
(rs-archive-clone), an output file written more than once (production-planning / retro), and the
declared deliverables with the check's undeclared-reference fact. The provider is never called:
these are pure case-builder cases.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from typing import cast

from builders.policy_cases import (
    act,
    clm,
    evd,
    evidence_record,
    evt,
    make_case,
    obl,
    obligation_record,
    plan_record,
    record,
    res,
)
from finishup.application.semantic_case import (
    TASK_INPUT_ITEM_PREFIX,
    CheckTimeChange,
    build_semantic_case,
    carries_task_inputs,
    review_input_manifest_to_json,
    semantic_case_to_prepared_payload,
)
from finishup.domain.events import (
    ActionKind,
    ActionRecordedPayload,
    ClaimKind,
    ClaimRecordedPayload,
    EvidenceImmutability,
    EvidenceKind,
    EvidenceRecordedPayload,
    ObligationPublishedPayload,
    ObligationStatus,
    PlanPublishedPayload,
    RequestedItem,
    RequestedItemKind,
    RequestedItemRole,
    ResultOutcome,
    ResultRecordedPayload,
)
from finishup.domain.privacy import ReviewContextProfile, ReviewSelectionPolicy
from finishup.domain.task_statement import RecordedTaskStatement
from finishup.domain.values import timestamp_from_string
from finishup.kernel.deterministic_checks import DeterministicCase
from finishup.ports.change_capture import (
    CHECK_CHANGE_MEDIA_TYPE,
    CheckChangeCapture,
    TaskInputFile,
)
from finishup.ports.objects import ObjectKind, ObjectMetadata, ObjectRef
from finishup.ports.semantic import SemanticCase
from finishup.protocol.canonical import JsonValue, strict_json_parse
from finishup.protocol.models import DataCategory
from unit.application.test_semantic_case import (
    _captured_case_values,  # pyright: ignore[reportPrivateUsage]
)

_TASK = "tsk_10000000-0000-4000-8000-000000000001"
_STATEMENT = (
    "Port the VBA UserForm in /app/vba/UserForm1.frm to Python as /app/form.py, following "
    "DESIGN.md."
)
_VBA = b'Private Sub CommandButton1_Click()\n    MsgBox "VBA_INPUT_MARKER"\nEnd Sub\n'


def _change(
    text: bytes = b"diff --git a/form.py b/form.py\n+def click(): pass\n",
    *,
    inputs: tuple[TaskInputFile, ...] = (),
) -> CheckTimeChange:
    return CheckTimeChange(
        ObjectRef(
            object_id="obj_00000000-0000-4000-8000-000000000901",
            plaintext_size=len(text) + 100,
            commitment="hmac-sha256:" + "9" * 64,
            envelope_digest="sha256:" + "a" * 64,
            encryption_format="yoetz-object/1",
            key_slot="task",
            metadata=ObjectMetadata(
                ObjectKind.CHANGE_CAPTURE,
                CHECK_CHANGE_MEDIA_TYPE,
                _TASK,
                datetime(2026, 10, 12, tzinfo=UTC),
            ),
        ),
        CheckChangeCapture(
            base="task_start",
            text=text,
            tracked_files=1,
            untracked_files=0,
            omitted_files=0,
            truncated=False,
            inputs=inputs,
        ),
    )


def _statement_case() -> DeterministicCase:
    plan = plan_record(PlanPublishedPayload(1, "Port the form", (obl(1),)), 1)
    obligation = obligation_record(
        ObligationPublishedPayload(
            obl(1),
            "Port the UserForm",
            "form.py behaves like the form",
            ObligationStatus.OPEN,
            requested_items=(
                RequestedItem(RequestedItemKind.FILE, "/app/form.py", RequestedItemRole.OUTPUT),
                RequestedItem(RequestedItemKind.FILE, "/app/notes.md", RequestedItemRole.INPUT),
                RequestedItem(
                    RequestedItemKind.FILE, "/app/out/plan.csv", RequestedItemRole.OUTPUT
                ),
            ),
        ),
        2,
    )
    claim = record(
        ClaimRecordedPayload(clm(1), ClaimKind.COMPLETION, "Ported", (), obligation_refs=(obl(1),)),
        3,
    )
    case = make_case(
        plans={1: plan},
        obligations={obl(1): obligation},
        claims={clm(1): claim},
        extra_refs=(clm(1), obl(1), evt(50)),
    )
    statement = RecordedTaskStatement(
        text=_STATEMENT,
        source_event_id=evt(50),
        source_family="session_opened",
        ingestion_sequence=50,
    )
    return replace(case, task_statement=statement)


def _build(
    case: DeterministicCase,
    *,
    change: CheckTimeChange | None = None,
    profile: ReviewContextProfile = ReviewContextProfile.EXPANDED,
    selection: ReviewSelectionPolicy | None = None,
    gaps: tuple[str, ...] = (),
    workspace_root: str | None = "/app",
) -> SemanticCase:
    return build_semantic_case(
        case_id="cas_10000000-0000-4000-8000-000000000001",
        frozen_case=case,
        dependency_digest="sha256:" + "b" * 64,
        findings=(),
        review_context_profile=profile,
        review_selection=selection or ReviewSelectionPolicy.for_profile(profile),
        policy_id="pvy_10000000-0000-4000-8000-000000000001",
        policy_version="1",
        captured_content_gaps=gaps,
        check_time_change=change,
        workspace_root=workspace_root,
    )


# --- Item 2: read-only task input files -------------------------------------------------------


def test_task_input_files_travel_as_repository_excerpts_linked_to_the_statement() -> None:
    change = _change(inputs=(TaskInputFile("vba/UserForm1.frm", _VBA, len(_VBA)),))

    semantic = _build(_statement_case(), change=change)

    item = next(item for item in semantic.items if item.item_id.startswith(TASK_INPUT_ITEM_PREFIX))
    assert item.item_id == f"{TASK_INPUT_ITEM_PREFIX}01"
    assert item.category is DataCategory.REPOSITORY_EXCERPT
    assert item.source_kind == "repository"
    assert str(evt(50)) in item.linked_subject_refs
    content = item.content.decode("utf-8")
    assert content.startswith(
        f"[FinishUP task input file vba/UserForm1.frm ({len(_VBA)} bytes): named by the task, "
        "unchanged since the task started"
    )
    assert "VBA_INPUT_MARKER" in content
    # Recorded on the input manifest like every other excerpt, and egress-counted with them.
    assert semantic.packet.input_manifest is not None
    manifest = review_input_manifest_to_json(semantic.packet.input_manifest)
    caller = cast(dict[str, JsonValue], manifest["caller_evidence"])
    assert item.item_id in cast(list[str], caller["item_ids"])
    assert item.item_id in {ref.excerpt_item_id for ref in semantic.packet.targeted_excerpts}


def test_task_inputs_rank_ahead_of_unreserved_output_and_are_cut_honestly() -> None:
    captured_case, captured, scope = _captured_case_values(b"competing-tool-output-marker")
    any_coverage = next(iter(captured_case.coverage_by_ref.values()))
    case = replace(
        captured_case,
        task_statement=RecordedTaskStatement(
            text=_STATEMENT,
            source_event_id=evt(50),
            source_family="session_opened",
            ingestion_sequence=50,
        ),
        allowed_ids=captured_case.allowed_ids | frozenset({evt(50)}),
        coverage_by_ref={**captured_case.coverage_by_ref, evt(50): any_coverage},
    )
    big = b"rule line\n" * 3_000
    change = _change(
        inputs=(TaskInputFile("DESIGN.md", big[:16_000], len(big)),),
    )

    semantic = build_semantic_case(
        case_id="cas_10000000-0000-4000-8000-000000000001",
        frozen_case=case,
        dependency_digest="sha256:" + "b" * 64,
        findings=(),
        review_context_profile=ReviewContextProfile.EXPANDED,
        review_selection=ReviewSelectionPolicy.for_profile(ReviewContextProfile.EXPANDED),
        policy_id="pvy_10000000-0000-4000-8000-000000000001",
        policy_version="1",
        captured_content=(captured,),
        captured_content_scope=scope,
        check_time_change=change,
    )

    order = [ref.excerpt_item_id for ref in semantic.packet.targeted_excerpts]
    task_input = f"{TASK_INPUT_ITEM_PREFIX}01"
    tool_output = next(ref for ref in order if ref.startswith("excerpt-"))
    assert order.index(task_input) < order.index(tool_output)
    # Stored as head and tail, so the excerpt is a partial view and the manifest says so.
    assert semantic.packet.input_manifest is not None
    manifest = review_input_manifest_to_json(semantic.packet.input_manifest)
    caller = cast(dict[str, JsonValue], manifest["caller_evidence"])
    assert caller["status"] == "partial"
    assert "truncated_payload" in cast(list[str], caller["omission_reasons"])


def test_task_inputs_need_the_statement_and_repository_excerpts_in_the_recipe() -> None:
    change = _change(inputs=(TaskInputFile("vba/UserForm1.frm", _VBA, len(_VBA)),))
    expanded = ReviewSelectionPolicy.for_profile(ReviewContextProfile.EXPANDED)
    without_repository = replace(
        expanded,
        excerpt_kinds=tuple(kind for kind in expanded.excerpt_kinds if kind != "repository"),
    )
    assert carries_task_inputs(expanded)
    assert not carries_task_inputs(without_repository)
    assert not carries_task_inputs(
        ReviewSelectionPolicy.for_profile(ReviewContextProfile.GOAL_AWARE)
    )

    semantic = _build(
        _statement_case(),
        change=change,
        profile=ReviewContextProfile.CUSTOM,
        selection=without_repository,
    )

    assert not any(item.item_id.startswith(TASK_INPUT_ITEM_PREFIX) for item in semantic.items)
    assert all(b"VBA_INPUT_MARKER" not in item.content for item in semantic.items)


# --- Item 4: the latest run per probe or path wins --------------------------------------------


def _probe_case(
    newest_command: str, first_command: str = "./probe.sh  --entries"
) -> DeterministicCase:
    """rs-archive-clone shape: a probe ran twice; only the first run's output was recorded."""

    claim = record(ClaimRecordedPayload(clm(1), ClaimKind.COMPLETION, "done", ()), 3)
    stale = EvidenceRecordedPayload(
        evd(11),
        EvidenceKind.COMMAND_OUTPUT,
        EvidenceImmutability.METADATA_ONLY,
        timestamp_from_string("2026-10-01T00:00:00.000Z"),
        description="probe: archive has 3 entries (STALE_PROBE_MARKER)",
    )
    return make_case(
        claims={clm(1): claim},
        actions={
            act(10): record(
                ActionRecordedPayload(act(10), ActionKind.COMMAND, "Run", command=first_command),
                10,
            ),
            act(20): record(
                ActionRecordedPayload(act(20), ActionKind.COMMAND, "Run", command=newest_command),
                20,
            ),
        },
        evidence={evd(11): evidence_record(stale, 11)},
        results={
            res(12): record(
                ResultRecordedPayload(
                    res(12), act(10), ResultOutcome.SUCCESS, 0, evidence_refs=(evd(11),)
                ),
                12,
            ),
            res(21): record(ResultRecordedPayload(res(21), act(20), ResultOutcome.SUCCESS, 0), 21),
        },
        extra_refs=(clm(1), act(10), act(20), evd(11), res(12), res(21)),
    )


def test_an_output_of_a_probe_that_ran_again_is_superseded_by_the_newer_run() -> None:
    semantic = _build(_probe_case("./probe.sh --entries"), workspace_root=None)

    stale = next(item for item in semantic.items if item.item_id == f"excerpt-{evd(11)}")
    # The same command (whitespace collapsed) ran again later; that run left no output, so the
    # older output is never presented as the latest one.
    assert stale.latest_for is None
    assert stale.superseded_by == (str(res(21)),)
    document = strict_json_parse(
        semantic_case_to_prepared_payload(semantic, {item.item_id for item in semantic.items})
    )
    assert isinstance(document, dict)
    rows = {
        cast(str, row["item_id"]): row
        for row in cast(list[dict[str, JsonValue]], document["items"])
    }
    assert rows[f"excerpt-{evd(11)}"]["superseded_by"] == [str(res(21))]


def test_a_different_command_never_supersedes_a_probe_output() -> None:
    semantic = _build(_probe_case("./probe.sh --other"), workspace_root=None)

    output = next(item for item in semantic.items if item.item_id == f"excerpt-{evd(11)}")
    assert output.latest_for == "command" and output.superseded_by == ()


def test_hook_runs_without_a_command_identity_never_supersede_each_other() -> None:
    case = _probe_case("omitted:structural", "omitted:structural")

    semantic = _build(case, workspace_root=None)

    output = next(item for item in semantic.items if item.item_id == f"excerpt-{evd(11)}")
    assert output.superseded_by == () and output.latest_for is None


def test_the_newest_artifact_at_one_path_wins() -> None:
    """production-planning / retro shape: an exploratory output was shown, not the final one."""

    def artifact(number: int, marker: str) -> EvidenceRecordedPayload:
        return EvidenceRecordedPayload(
            evd(number),
            EvidenceKind.ARTIFACT,
            EvidenceImmutability.METADATA_ONLY,
            timestamp_from_string("2026-10-01T00:00:00.000Z"),
            reference="out/plan.csv",
            description=marker,
        )

    claim = record(
        ClaimRecordedPayload(clm(1), ClaimKind.COMPLETION, "done", (evd(30), evd(40))), 50
    )
    case = make_case(
        claims={clm(1): claim},
        evidence={
            evd(30): evidence_record(artifact(30, "EXPLORATORY_OUTPUT"), 30),
            evd(40): evidence_record(artifact(40, "FINAL_OUTPUT"), 40),
        },
        extra_refs=(clm(1), evd(30), evd(40)),
    )

    semantic = _build(case, workspace_root=None)

    items = {item.item_id: item for item in semantic.items}
    assert items[f"excerpt-{evd(30)}"].superseded_by == (str(evd(40)),)
    assert items[f"excerpt-{evd(40)}"].superseded_by == ()
    order = [ref.excerpt_item_id for ref in semantic.packet.targeted_excerpts]
    assert order.index(f"excerpt-{evd(40)}") < order.index(f"excerpt-{evd(30)}")


# --- Item 5: the declared deliverables and their facts ----------------------------------------


def test_declared_deliverables_reach_the_packet_with_the_check_facts() -> None:
    change = _change(
        b"FinishUP check-time change: captured by the FinishUP service when this check ran; the "
        b"agent did not supply it.\n"
        b"Changed files: 1 tracked, 0 untracked. Not shown: 0.\n"
        b"Files:\n"
        b"  M form.py (+1 -1)\n"
        b"End of header. The unified diff follows.\n"
        b"diff --git a/form.py b/form.py\n+def click(): pass\n"
    )

    semantic = _build(
        _statement_case(),
        change=change,
        gaps=("content_capture_unavailable", "deliverable_references_undeclared_file"),
    )

    assert semantic.packet.obligation_item_ids[0] == "declared-deliverables"
    item = next(item for item in semantic.items if item.item_id == "declared-deliverables")
    assert item.category is DataCategory.OBLIGATION_TEXT
    assert item.source_ref == str(obl(1))
    body = strict_json_parse(item.content)
    assert isinstance(body, dict)
    assert body["kind"] == "declared_deliverables"
    assert body["facts"] == ["deliverable_references_undeclared_file"]
    rows = cast(list[dict[str, JsonValue]], body["deliverables"])
    # Only role: output items; the declared input is not a deliverable.
    assert [(row["value"], row["in_check_time_change"]) for row in rows] == [
        ("/app/form.py", "modified"),
        ("/app/out/plan.csv", "not_changed"),
    ]


def test_no_declared_deliverable_means_no_row_set() -> None:
    semantic = _build(make_case(extra_refs=()), change=_change(), workspace_root=None)

    assert "declared-deliverables" not in {item.item_id for item in semantic.items}
