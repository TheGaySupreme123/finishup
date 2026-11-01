"""Reserved room, wire order and freshness marks in the AI-powered review packet (issue #907).

Every captured edit and tool output below is produced by the real hook capture path from a
current host payload shape (Codex ``apply_patch`` ``PostToolUse``, Claude Code ``Edit``/``Write``
``PostToolUse`` and Cursor ``postToolUse``), never from pre-normalised rows. Verification runs are
recorded the way an agent records them: an action carrying the command, a result carrying the
outcome, and evidence carrying the output.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Literal, cast

import pytest

from builders.policy_cases import (
    act,
    clm,
    evd,
    evidence_record,
    evt,
    finding_record,
    fnd,
    make_case,
    obl,
    obligation_record,
    plan_record,
    record,
    res,
)
from finishup.adapters.integrations.observation_local import session_commitment_from_codex_id
from finishup.application import semantic_case as semantic_case_module
from finishup.application.semantic_case import (
    MAX_PRIOR_FINDINGS,
    CapturedContentScope,
    CapturedSemanticContent,
    assemble_filtered_review_packet,
    bounded_case_envelope,
    build_semantic_case,
    captured_edit_paths,
    review_input_manifest_to_json,
    review_packet_disclosure_result,
    semantic_case_to_prepared_payload,
)
from finishup.cli import observe_hooks as observe_hooks_module
from finishup.cli.observe_hooks import map_hook_payload_to_envelope
from finishup.domain.events import (
    ActionKind,
    ActionRecordedPayload,
    ClaimKind,
    ClaimRecordedPayload,
    EvidenceContentAvailability,
    EvidenceDigestBinding,
    EvidenceDigestProvenance,
    EvidenceDigestSubject,
    EvidenceKind,
    EvidenceRecordedPayload,
    MissingForAssessmentItem,
    ObligationPublishedPayload,
    ObligationStatus,
    PlanPublishedPayload,
    ResultOutcome,
    ResultRecordedPayload,
)
from finishup.domain.observation import (
    ObservationContentKind,
    ObservationContentManifest,
    ObservationSource,
)
from finishup.domain.privacy import ReviewContextProfile, ReviewSelectionPolicy
from finishup.domain.receipts import SEMANTIC_PRIOR_FINDINGS_OVER_LIMIT_GAP
from finishup.domain.values import (
    ActionId,
    EvidenceId,
    FindingId,
    ResultId,
    object_id,
    timestamp_from_string,
)
from finishup.kernel.deterministic_checks import DeterministicCase, FindingBasisRef
from finishup.kernel.projections import (
    EvidenceProjectionRecord,
    FindingProjectionRecord,
    PendingMissingForAssessment,
    ProjectionRecord,
)
from finishup.ports.objects import ObjectKind, ObjectMetadata, ObjectRef
from finishup.ports.semantic import SemanticCase
from finishup.protocol.canonical import JsonValue, strict_json_parse
from finishup.protocol.coverage import EvidenceImmutability

type Host = Literal["codex", "claude", "cursor"]

_KEY = b"k" * 32
_WORKSPACE = "/srv/dev/proj"
_TASK = "tsk_10000000-0000-4000-8000-000000000001"
_SESSION = "ses_10000000-0000-4000-8000-000000000001"
_WORKSPACE_COMMITMENT = "hmac-sha256:" + "8" * 64
_PHASE = "sha256:" + "4" * 64
_PATHS = ("app/alpha.py", "app/beta.py", "app/gamma.py", "lib/delta.py", "lib/epsilon.py")
_PROFILE: Mapping[Host, str] = {
    "codex": ObservationSource.CODEX_HOOK.value,
    "claude": "claude-code-ordinary-observation-v1",
    "cursor": "cursor-ordinary-observation-v1",
}
_SOURCE: Mapping[Host, ObservationSource] = {
    "codex": ObservationSource.CODEX_HOOK,
    "claude": ObservationSource.CLAUDE_HOOK,
    "cursor": ObservationSource.CURSOR_HOOK,
}


def _capture(host: Host, payload: dict[str, JsonValue]) -> tuple[ObservationContentKind, bytes]:
    """Run one real host payload through the hook's own content selection."""

    envelope = map_hook_payload_to_envelope(
        "PostToolUse",
        payload,
        session_commitment=session_commitment_from_codex_id(_KEY, "selection-session"),
        event_ordinal=1,
        key_material=_KEY,
        source=_SOURCE[host],
    )
    chunks, truncated = observe_hooks_module._visible_content_chunks(  # pyright: ignore[reportPrivateUsage]
        "PostToolUse", payload, envelope=envelope, workspace_locator=_WORKSPACE
    )
    assert not truncated
    kinds = {chunk.content_kind for chunk in chunks}
    assert len(kinds) == 1, kinds
    return chunks[0].content_kind, b"".join(chunk.content for chunk in chunks)


def _edit_payload(host: Host, path: str, marker: str, call: int) -> dict[str, JsonValue]:
    absolute = f"{_WORKSPACE}/{path}"
    if host == "codex":
        patch = (
            "*** Begin Patch\n"
            f"*** Update File: {absolute}\n"
            "@@ def handler(key):\n"
            "-    return lookup(key)\n"
            f"+    return lookup({marker})\n"
            "*** End Patch\n"
        )
        return {
            "session_id": "019a0000-0000-7000-8000-000000000001",
            "transcript_path": f"{_WORKSPACE}/.codex/sessions/rollout.jsonl",
            "cwd": _WORKSPACE,
            "hook_event_name": "PostToolUse",
            "model": "gpt-5.5-codex",
            "permission_mode": "default",
            "turn_id": f"turn-{call}",
            "tool_name": "apply_patch",
            "tool_use_id": f"call_patch_{call}",
            "tool_input": {"command": patch},
            "tool_response": (
                "Exit code: 0\nWall time: 0.1 seconds\nOutput:\n"
                f"Success. Updated the following files:\nM {absolute}\n"
            ),
        }
    if host == "claude":
        if call % 2:
            return {
                "session_id": "5b3c1d2e-0000-4000-8000-000000000001",
                "transcript_path": "/srv/dev/.claude/projects/proj/session.jsonl",
                "cwd": _WORKSPACE,
                "permission_mode": "acceptEdits",
                "hook_event_name": "PostToolUse",
                "tool_name": "Edit",
                "tool_use_id": f"toolu_{call:04d}",
                "tool_input": {
                    "file_path": absolute,
                    "old_string": "return lookup(key)",
                    "new_string": f"return lookup({marker})",
                    "replace_all": False,
                },
                "tool_response": {
                    "filePath": absolute,
                    "oldString": "return lookup(key)",
                    "newString": f"return lookup({marker})",
                    "originalFile": "ORIGINAL_FILE_CANARY",
                    "structuredPatch": [
                        {
                            "oldStart": 2,
                            "oldLines": 1,
                            "newStart": 2,
                            "newLines": 1,
                            "lines": ["-    return lookup(key)", f"+    return lookup({marker})"],
                        }
                    ],
                    "userModified": False,
                    "replaceAll": False,
                },
            }
        content = f"def handler(key):\n    return lookup({marker})\n"
        return {
            "session_id": "5b3c1d2e-0000-4000-8000-000000000001",
            "transcript_path": "/srv/dev/.claude/projects/proj/session.jsonl",
            "cwd": _WORKSPACE,
            "permission_mode": "acceptEdits",
            "hook_event_name": "PostToolUse",
            "tool_name": "Write",
            "tool_use_id": f"toolu_{call:04d}",
            "tool_input": {"file_path": absolute, "content": content},
            "tool_response": {
                "type": "update",
                "filePath": absolute,
                "content": content,
                "structuredPatch": [],
                "originalFile": "ORIGINAL_FILE_CANARY",
            },
        }
    return {
        "conversation_id": "cursor-conv-1",
        "generation_id": f"gen-{call}",
        "model": "claude-opus-4-7-thinking-max",
        "hook_event_name": "postToolUse",
        "cursor_version": "3.17.8",
        "workspace_roots": [_WORKSPACE],
        "user_email": None,
        "transcript_path": None,
        "tool_name": "Write",
        "tool_use_id": f"t{call}",
        "tool_input": {
            "path": absolute,
            "contents": f"def handler(key):\n    return lookup({marker})\n",
        },
        "tool_output": '{"path":"' + absolute + '","ok":true}',
        "cwd": _WORKSPACE,
        "duration": 12,
    }


def _output_payload(host: Host, text: str, call: int) -> dict[str, JsonValue]:
    if host == "codex":
        return {
            "session_id": "019a0000-0000-7000-8000-000000000001",
            "transcript_path": f"{_WORKSPACE}/.codex/sessions/rollout.jsonl",
            "cwd": _WORKSPACE,
            "hook_event_name": "PostToolUse",
            "model": "gpt-5.5-codex",
            "permission_mode": "default",
            "turn_id": f"turn-out-{call}",
            "tool_name": "shell",
            "tool_use_id": f"call_shell_{call}",
            "tool_input": {"command": ["bash", "-lc", "cat app/alpha.py"]},
            "tool_response": f"Exit code: 0\nWall time: 0.1 seconds\nOutput:\n{text}\n",
        }
    if host == "claude":
        return {
            "session_id": "5b3c1d2e-0000-4000-8000-000000000001",
            "transcript_path": "/srv/dev/.claude/projects/proj/session.jsonl",
            "cwd": _WORKSPACE,
            "permission_mode": "acceptEdits",
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_use_id": f"toolu_out_{call:04d}",
            "tool_input": {"command": "cat app/alpha.py", "description": "Read the module"},
            "tool_response": {"stdout": text, "stderr": "", "interrupted": False},
        }
    return {
        "conversation_id": "cursor-conv-1",
        "generation_id": f"gen-out-{call}",
        "model": "claude-opus-4-7-thinking-max",
        "hook_event_name": "postToolUse",
        "cursor_version": "3.17.8",
        "workspace_roots": [_WORKSPACE],
        "user_email": None,
        "transcript_path": None,
        "tool_name": "Shell",
        "tool_use_id": f"t-out-{call}",
        "tool_input": {"command": "cat app/alpha.py"},
        "tool_output": text,
        "cwd": _WORKSPACE,
        "duration": 5,
    }


def _expanded_16() -> ReviewSelectionPolicy:
    """The Expanded selection at the Phase 1a count of 16 excerpts (issue #907).

    Phase 1b (#944) raised Expanded to 64 excerpts. These cases pin how the 1a selection fills and
    cuts a fixed count, so they keep the 16-slot count explicitly.
    """

    return replace(
        ReviewSelectionPolicy.for_profile(ReviewContextProfile.EXPANDED), max_excerpts=16
    )


@dataclass(frozen=True, slots=True)
class _Ledger:
    case: DeterministicCase
    captured: tuple[CapturedSemanticContent, ...]
    scope: CapturedContentScope
    newest_edit_for_path: Mapping[str, EvidenceId]
    edit_path: Mapping[EvidenceId, str]
    outputs: tuple[EvidenceId, ...]
    verification: Mapping[str, tuple[EvidenceId, ...]]
    run_actions: Mapping[EvidenceId, ActionId]


def _captured_row(
    number: int,
    ref: EvidenceId,
    content: bytes,
    kind: ObservationContentKind,
    profile: str,
) -> tuple[EvidenceProjectionRecord, CapturedSemanticContent]:
    object_value = object_id(f"obj_00000000-0000-4000-8000-{number:012x}")
    digest = "sha256:" + hashlib.sha256(content).hexdigest()
    envelope = "sha256:" + hashlib.sha256(b"envelope-%d" % number).hexdigest()
    payload = EvidenceRecordedPayload(
        evidence_id=ref,
        evidence_kind=EvidenceKind.OTHER,
        strength=EvidenceImmutability.IMMUTABLE_SNAPSHOT,
        observed_at=timestamp_from_string("2026-09-27T00:00:00.000Z"),
        captured_object_id=object_value,
        content_digest=digest,
        description=f"Observation-captured {kind.value} bytes part=1/1",
        digest_binding=EvidenceDigestBinding(
            subject=EvidenceDigestSubject.BOUNDED_EXCERPT,
            content_availability=EvidenceContentAvailability.CAPTURED,
            byte_count=len(content),
            provenance=EvidenceDigestProvenance.OBSERVATION_CAPTURED,
        ),
    )
    captured = CapturedSemanticContent(
        object_ref=ObjectRef(
            object_id=object_value,
            plaintext_size=len(content) + 256,
            commitment="hmac-sha256:" + "6" * 64,
            envelope_digest=envelope,
            encryption_format="yoetz-object/1",
            key_slot="task",
            metadata=ObjectMetadata(
                ObjectKind.CAPTURED_CONTENT,
                "application/vnd.yoetz.observation-content+json",
                _TASK,
                datetime(2026, 9, 27, tzinfo=UTC),
            ),
        ),
        manifest=ObservationContentManifest(
            object_id=object_value,
            envelope_digest=envelope,
            content_kind=kind,
            part_index=0,
            part_count=1,
            redacted=False,
            content_digest=digest,
            content_bytes=len(content),
            correlation_identity=f"tool-use-{number}",
            source_commitment="hmac-sha256:" + hashlib.sha256(b"%d" % number).hexdigest(),
        ),
        content=content,
        task_id=_TASK,
        session_id=_SESSION,
        workspace_commitment=_WORKSPACE_COMMITMENT,
        phase_identity=_PHASE,
        capture_profile=profile,
    )
    return evidence_record(payload, number), captured


def _ledger(
    host: Host,
    *,
    outputs: int = 30,
    edits_per_path: int = 4,
    id_of: Callable[[int], EvidenceId] = evd,
    output_text: Callable[[int], str] | None = None,
    findings: Mapping[FindingId, FindingProjectionRecord] | None = None,
) -> _Ledger:
    """20 edits over 5 paths, verification runs and captured tool output, in recorded order."""

    evidence: dict[EvidenceId, EvidenceProjectionRecord] = {}
    captured: list[CapturedSemanticContent] = []
    newest: dict[str, EvidenceId] = {}
    edit_path: dict[EvidenceId, str] = {}
    output_refs: list[EvidenceId] = []
    actions: dict[ActionId, ProjectionRecord[ActionRecordedPayload]] = {}
    results: dict[ResultId, ProjectionRecord[ResultRecordedPayload]] = {}
    verification: dict[str, list[EvidenceId]] = {"pytest": [], "ruff": []}
    run_actions: dict[EvidenceId, ActionId] = {}
    frontier = 3
    call = 0

    def next_number() -> int:
        nonlocal frontier
        frontier += 1
        assert frontier < 100
        return frontier

    def add_edit(path: str, round_index: int) -> None:
        nonlocal call
        call += 1
        number = next_number()
        ref = id_of(number)
        kind, content = _capture(
            host, _edit_payload(host, path, f"repair_{round_index}_{path.replace('/', '_')}", call)
        )
        row, item = _captured_row(number, ref, content, kind, _PROFILE[host])
        evidence[ref] = row
        captured.append(item)
        newest[path] = ref
        edit_path[ref] = path

    def add_output(index: int) -> None:
        nonlocal call
        call += 1
        number = next_number()
        ref = id_of(number)
        text = (
            output_text(index)
            if output_text is not None
            else f"def handler(key):\n    return lookup(key)  # read {index}\n"
        )
        kind, content = _capture(host, _output_payload(host, text, call))
        row, item = _captured_row(number, ref, content, kind, _PROFILE[host])
        evidence[ref] = row
        captured.append(item)
        output_refs.append(ref)

    def add_run(tool: str, command: str, outcome: ResultOutcome, output: str) -> None:
        action_number = next_number()
        evidence_number = next_number()
        result_number = next_number()
        action_ref = act(action_number)
        result_ref = res(result_number)
        evidence_ref = id_of(evidence_number)
        actions[action_ref] = record(
            ActionRecordedPayload(action_ref, ActionKind.COMMAND, f"Run {tool}", command=command),
            action_number,
        )
        evidence[evidence_ref] = evidence_record(
            EvidenceRecordedPayload(
                evidence_ref,
                EvidenceKind.TEST_RESULT if tool == "pytest" else EvidenceKind.COMMAND_OUTPUT,
                EvidenceImmutability.METADATA_ONLY,
                timestamp_from_string("2026-09-27T00:00:00.000Z"),
                description=output,
            ),
            evidence_number,
        )
        results[result_ref] = record(
            ResultRecordedPayload(
                result_ref,
                action_ref,
                outcome,
                0 if outcome is ResultOutcome.SUCCESS else 1,
                evidence_refs=(evidence_ref,),
            ),
            result_number,
        )
        verification[tool].append(evidence_ref)
        run_actions[evidence_ref] = action_ref

    for round_index in range(edits_per_path):
        for path in _PATHS:
            add_edit(path, round_index)
        if round_index == 0:
            add_run("pytest", "pytest -q", ResultOutcome.FAILURE, "E assert lookup(key)\n1 failed")
            add_run("ruff", "ruff check .", ResultOutcome.SUCCESS, "All checks passed! (run 1)")
        if round_index == 1:
            add_run("pytest", "pytest -q", ResultOutcome.FAILURE, "E KeyError\n1 failed")
        for index in range(
            round_index * outputs // max(1, edits_per_path),
            (round_index + 1) * outputs // max(1, edits_per_path),
        ):
            add_output(index)
    add_run("pytest", "pytest -q", ResultOutcome.SUCCESS, "12 passed in 0.31s")
    add_run("ruff", "ruff check .", ResultOutcome.SUCCESS, "All checks passed! (run 2)")

    plan = plan_record(PlanPublishedPayload(1, "Repair key lookups", (obl(1),)), 1)
    obligation = obligation_record(
        ObligationPublishedPayload(obl(1), "Repair lookups", "tests pass", ObligationStatus.OPEN), 2
    )
    claim = record(
        ClaimRecordedPayload(
            clm(1), ClaimKind.COMPLETION, "Lookups repaired", (), obligation_refs=(obl(1),)
        ),
        3,
    )
    case = make_case(
        plans={1: plan},
        obligations={obl(1): obligation},
        claims={clm(1): claim},
        actions=actions,
        results=results,
        evidence=evidence,
        findings=findings,
        extra_refs=(clm(1), obl(1)),
    )
    scope = CapturedContentScope(
        task_id=_TASK,
        session_id=_SESSION,
        workspace_commitment=_WORKSPACE_COMMITMENT,
        authorized_profiles=(_PROFILE[host],),
        phase_bindings=tuple(
            sorted(
                ((str(item_ref), _PHASE) for item_ref in _captured_refs(evidence)),
                key=lambda pair: pair[0].encode("ascii"),
            )
        ),
    )
    return _Ledger(
        case=case,
        captured=tuple(captured),
        scope=scope,
        newest_edit_for_path=newest,
        edit_path=edit_path,
        outputs=tuple(output_refs),
        verification={tool: tuple(refs) for tool, refs in verification.items()},
        run_actions=run_actions,
    )


def _captured_refs(
    evidence: Mapping[EvidenceId, EvidenceProjectionRecord],
) -> tuple[EvidenceId, ...]:
    return tuple(
        ref
        for ref, row in evidence.items()
        if row.payload is not None and row.payload.captured_object_id is not None
    )


def _build(
    ledger: _Ledger,
    selection: ReviewSelectionPolicy | None = None,
    *,
    prepared_byte_ceiling: int | None = None,
) -> SemanticCase:
    return build_semantic_case(
        case_id="cas_10000000-0000-4000-8000-000000000001",
        frozen_case=ledger.case,
        dependency_digest="sha256:" + "b" * 64,
        findings=(),
        review_context_profile=ReviewContextProfile.EXPANDED,
        review_selection=selection or _expanded_16(),
        policy_id="pvy_10000000-0000-4000-8000-000000000001",
        policy_version="1",
        captured_content=ledger.captured,
        captured_content_scope=ledger.scope,
        prepared_byte_ceiling=prepared_byte_ceiling,
    )


def _prepared_items(semantic: SemanticCase) -> list[dict[str, JsonValue]]:
    document = strict_json_parse(
        semantic_case_to_prepared_payload(semantic, {item.item_id for item in semantic.items})
    )
    assert isinstance(document, dict)
    assert document["schema"] == "yoetz.review-packet-case/2"
    rows = document["items"]
    assert isinstance(rows, list)
    return [cast(dict[str, JsonValue], row) for row in rows]


# --- Acceptance criterion 3: reserved room -------------------------------------------------


@pytest.mark.parametrize("host", ["codex", "claude", "cursor"])
def test_reserved_room_carries_newest_hunk_per_path_and_latest_run_per_command(
    host: Host,
) -> None:
    ledger = _ledger(host)
    semantic = _build(ledger)
    excerpts = semantic.packet.targeted_excerpts
    items = {item.item_id: item for item in semantic.items}
    assert len(excerpts) == 16
    assert len(ledger.captured) == 50

    selected_sources = [items[row.excerpt_item_id].source_ref for row in excerpts]
    # Newest hunk of every changed path, marked as such.
    for path, ref in ledger.newest_edit_for_path.items():
        item = items[f"excerpt-{ref}"]
        assert item.source_kind == "diff", path
        assert item.latest_for == "path"
        assert item.superseded_by == ()
    # Latest output per verification command, with the last failure kept beside the later pass.
    pytest_runs = ledger.verification["pytest"]
    ruff_runs = ledger.verification["ruff"]
    assert items[f"excerpt-{pytest_runs[-1]}"].latest_for == "command"
    assert items[f"excerpt-{pytest_runs[-2]}"].superseded_by == (str(pytest_runs[-1]),)
    assert items[f"excerpt-{ruff_runs[-1]}"].latest_for == "command"
    assert f"excerpt-{pytest_runs[0]}" not in items
    assert f"excerpt-{ruff_runs[0]}" not in items
    reserved_runs = (pytest_runs[-1], pytest_runs[-2], ruff_runs[-1])
    reserved = {
        *(str(ref) for ref in ledger.newest_edit_for_path.values()),
        *(str(ref) for ref in reserved_runs),
        # Expanded carries exact command text; a reserved run's command travels beside it.
        *(str(ledger.run_actions[ref]) for ref in reserved_runs),
    }
    # Reserved room comes first.
    assert set(selected_sources[: len(reserved)]) == reserved
    # Older hunks of a changed path are still code under review (a later hunk elsewhere in the
    # file leaves them in place): they follow the reserved room, marked, ahead of tool output.
    newest_edits = {str(ref) for ref in ledger.newest_edit_for_path.values()}
    older_hunks = {str(ref) for ref in ledger.edit_path} - newest_edits
    rest = selected_sources[len(reserved) :]
    assert rest and set(rest) <= older_hunks
    assert all(items[f"excerpt-{ref}"].superseded_by for ref in rest)
    # One item per slot: every excerpt is one recorded source, never a concatenation.
    assert len(set(selected_sources)) == len(selected_sources)


@pytest.mark.parametrize("host", ["codex", "claude", "cursor"])
def test_older_hunks_are_marked_superseded_by_the_newest_hunk_for_their_path(host: Host) -> None:
    ledger = _ledger(host, outputs=0)
    semantic = _build(ledger)
    items = {item.item_id: item for item in semantic.items if item.section == "excerpt"}
    superseded = [
        item for item in items.values() if item.source_kind == "diff" and item.superseded_by
    ]
    assert superseded, "room left after the reserved slots carries older hunks, marked"
    for item in superseded:
        path = ledger.edit_path[cast(EvidenceId, item.source_ref)]
        assert item.superseded_by == (str(ledger.newest_edit_for_path[path]),)
        assert item.latest_for is None

    rows = {cast(str, row["item_id"]): row for row in _prepared_items(semantic)}
    for item in superseded:
        assert rows[item.item_id]["superseded_by"] == list(item.superseded_by)
        assert "latest_for" not in rows[item.item_id]
    for ref in ledger.newest_edit_for_path.values():
        assert rows[f"excerpt-{ref}"]["latest_for"] == "path"
        assert "superseded_by" not in rows[f"excerpt-{ref}"]


def test_kea_shape_repair_hunk_is_current_and_the_pre_repair_hunk_is_superseded() -> None:
    """Replay of the kea case: a Codex repair of the same file supersedes the String(key) hunk."""

    evidence: dict[EvidenceId, EvidenceProjectionRecord] = {}
    captured: list[CapturedSemanticContent] = []
    contents: dict[str, bytes] = {}
    for number, marker in ((10, "String(key)"), (20, "key")):
        payload = _edit_payload("codex", "src/map-tracking.ts", marker, number)
        kind, content = _capture("codex", payload)
        row, item = _captured_row(number, evd(number), content, kind, _PROFILE["codex"])
        evidence[evd(number)] = row
        captured.append(item)
        contents[marker] = content
    ledger = _Ledger(
        case=make_case(evidence=evidence),
        captured=tuple(captured),
        scope=CapturedContentScope(
            task_id=_TASK,
            session_id=_SESSION,
            workspace_commitment=_WORKSPACE_COMMITMENT,
            authorized_profiles=(_PROFILE["codex"],),
            phase_bindings=((str(evd(10)), _PHASE), (str(evd(20)), _PHASE)),
        ),
        newest_edit_for_path={"src/map-tracking.ts": evd(20)},
        edit_path={evd(10): "src/map-tracking.ts", evd(20): "src/map-tracking.ts"},
        outputs=(),
        verification={},
        run_actions={},
    )
    rows = [row for row in _prepared_items(_build(ledger)) if row["section"] == "excerpt"]
    assert [row["source_ref"] for row in rows] == [str(evd(10)), str(evd(20))]
    old, new = rows
    assert old["superseded_by"] == [str(evd(20))] and old["occurred_order"] == 10
    assert new["latest_for"] == "path" and new["occurred_order"] == 20
    assert new["content"] == contents["key"].decode("utf-8")
    assert "lookup(String(key))" in cast(str, old["content"])


def test_a_failed_edit_neither_is_current_code_nor_supersedes_the_applied_hunk() -> None:
    applied_payload = _edit_payload("claude", "app/alpha.py", "applied_fix", 1)
    failed_payload = dict(_edit_payload("claude", "app/alpha.py", "failed_fix", 2))
    failed_payload["hook_event_name"] = "PostToolUseFailure"
    failed_payload["error"] = "String to replace not found in file."
    failed_payload.pop("tool_response")
    evidence: dict[EvidenceId, EvidenceProjectionRecord] = {}
    captured: list[CapturedSemanticContent] = []
    for number, payload in ((10, applied_payload), (20, failed_payload)):
        kind, content = _capture("claude", payload)
        row, item = _captured_row(number, evd(number), content, kind, _PROFILE["claude"])
        evidence[evd(number)] = row
        captured.append(item)
    assert b'"edit_outcome":"failed"' in captured[1].content
    ledger = _Ledger(
        case=make_case(evidence=evidence),
        captured=tuple(captured),
        scope=CapturedContentScope(
            task_id=_TASK,
            session_id=_SESSION,
            workspace_commitment=_WORKSPACE_COMMITMENT,
            authorized_profiles=(_PROFILE["claude"],),
            phase_bindings=((str(evd(10)), _PHASE), (str(evd(20)), _PHASE)),
        ),
        newest_edit_for_path={"app/alpha.py": evd(10)},
        edit_path={evd(10): "app/alpha.py", evd(20): "app/alpha.py"},
        outputs=(),
        verification={},
        run_actions={},
    )
    items = {item.source_ref: item for item in _build(ledger).items if item.section == "excerpt"}
    assert items[str(evd(10))].latest_for == "path"
    assert items[str(evd(20))].latest_for is None
    assert items[str(evd(20))].superseded_by == ()


# --- Acceptance criterion 4: summary lines survive ------------------------------------------


@pytest.mark.parametrize("host", ["codex", "claude", "cursor"])
def test_long_test_output_keeps_its_head_and_final_summary_line_with_the_cut_marked(
    host: Host,
) -> None:
    summary = "=========== 3 failed, 1255 passed, 123 snapshots in 19.15s ==========="

    def text(index: int) -> str:
        body = "".join(f"PASS tests/unit/case_{line:05d}.test.ts\n" for line in range(1_400))
        return f"$ npx jest --ci run={index}\n" + body + summary

    ledger = _ledger(host, outputs=1, edits_per_path=1, output_text=text)
    semantic = _build(ledger)
    output_ref = str(ledger.outputs[0])
    item = next(
        item
        for item in semantic.items
        if item.section == "excerpt" and item.source_ref == output_ref
    )
    content = item.content.decode("utf-8")
    assert len(ledger.captured[-1].content) > 16_384
    assert item.content_bytes <= 16_384
    assert "npx jest --ci run=0" in content
    assert summary in content
    assert "bytes elided here; head and tail kept]" in content
    assert "truncated_payload" in semantic.packet.coverage.known_gaps


def test_agent_recorded_output_clipped_by_a_narrow_bound_keeps_its_tail() -> None:
    body = "line of output\n" * 400 + "FINAL: 8 suites, 1258 tests passed"
    evidence = {
        evd(4): evidence_record(
            EvidenceRecordedPayload(
                evd(4),
                EvidenceKind.TEST_RESULT,
                EvidenceImmutability.METADATA_ONLY,
                timestamp_from_string("2026-09-27T00:00:00.000Z"),
                description=body,
            ),
            4,
        )
    }
    selection = _expanded_16()
    narrow = ReviewSelectionPolicy(
        sections=selection.sections,
        excerpt_kinds=selection.excerpt_kinds,
        relevance=selection.relevance,
        include_finding_prose=selection.include_finding_prose,
        include_exact_command_text=selection.include_exact_command_text,
        max_timeline_items=selection.max_timeline_items,
        max_assessments=selection.max_assessments,
        max_change_observations=selection.max_change_observations,
        max_excerpts=selection.max_excerpts,
        max_omissions=selection.max_omissions,
        max_excerpt_bytes=1_024,
        max_total_excerpt_bytes=selection.max_total_excerpt_bytes,
    )
    semantic = build_semantic_case(
        case_id="cas_10000000-0000-4000-8000-000000000001",
        frozen_case=make_case(evidence=evidence),
        dependency_digest="sha256:" + "b" * 64,
        findings=(),
        review_context_profile=ReviewContextProfile.CUSTOM,
        review_selection=narrow,
        policy_id="pvy_10000000-0000-4000-8000-000000000001",
        policy_version="1",
    )
    item = next(item for item in semantic.items if item.section == "excerpt")
    assert item.content_bytes == 1_024
    assert item.content.startswith(b"line of output")
    assert item.content.endswith(b"FINAL: 8 suites, 1258 tests passed")


# --- Acceptance criterion 5: wire order -----------------------------------------------------


def test_every_item_and_excerpt_carries_occurred_order_and_excerpts_are_in_recorded_order() -> None:
    ledger = _ledger("claude", outputs=6, edits_per_path=2)
    rows = _prepared_items(_build(ledger))
    assert rows
    assert all(type(row["occurred_order"]) is int for row in rows)
    excerpt_orders = [
        cast(int, row["occurred_order"]) for row in rows if row["section"] == "excerpt"
    ]
    assert excerpt_orders == sorted(excerpt_orders)
    assert len(set(excerpt_orders)) == len(excerpt_orders)


def test_shuffling_evidence_ids_does_not_change_the_order_the_reviewer_sees() -> None:
    """Evidence ids are random UUIDs; the reviewer's order must come from the ledger alone."""

    def reversed_ids(number: int) -> EvidenceId:
        return evd(200 - number)

    def content_order(semantic: SemanticCase) -> list[str]:
        return [
            cast(str, row["content"])
            for row in _prepared_items(semantic)
            if row["section"] == "excerpt"
        ]

    ascending = _build(_ledger("codex", outputs=8, edits_per_path=2))
    descending = _build(_ledger("codex", outputs=8, edits_per_path=2, id_of=reversed_ids))
    assert content_order(ascending) == content_order(descending)
    assert len(content_order(ascending)) == 16


# --- Acceptance criterion 8: one item per slot ------------------------------------------------


@pytest.mark.parametrize("host", ["codex", "claude", "cursor"])
def test_no_excerpt_concatenates_several_recorded_outputs(host: Host) -> None:
    ledger = _ledger(host)
    semantic = _build(ledger)
    captured_by_object = {item.object_ref.object_id: item.content for item in ledger.captured}
    sources: dict[str, bytes] = {}
    for ref, row in ledger.case.projection.evidence.items():
        assert row.payload is not None
        sources[str(ref)] = (
            captured_by_object[str(row.payload.captured_object_id)]
            if row.payload.captured_object_id is not None
            else cast(str, row.payload.description).encode("utf-8")
        )
    for ref, row in ledger.case.projection.actions.items():
        assert row.payload is not None
        sources[str(ref)] = cast(str, row.payload.command).encode("utf-8")
    for excerpt in semantic.packet.targeted_excerpts:
        item = next(item for item in semantic.items if item.item_id == excerpt.excerpt_item_id)
        source = sources[item.source_ref]
        # Whole, one part of, or the marked head and tail of exactly this one source.
        pieces = item.content.split(b"\n[finishup: ")
        assert source.startswith(pieces[0]) or pieces[0] in source
        others = [
            content
            for content in captured_by_object.values()
            if content != source and len(content) > 64
        ]
        assert not any(other in item.content for other in others)
    assert len(semantic.packet.targeted_excerpts) <= 16


# --- Planning below the channel ceiling -------------------------------------------------------


def test_excerpt_selection_plans_the_prepared_document_below_the_channel_ceiling() -> None:
    """Larger excerpts never turn a reviewable case into a channel-ceiling denial.

    Control characters in captured terminal output cost six bytes each once the provider
    document is JSON-encoded, so 128 KiB of approved excerpt bytes can exceed the 256 KiB channel
    ceiling. Selection measures the exact prepared document and drops the lowest-ranked
    excerpts, disclosed like any other budget omission.
    """

    def noisy(index: int) -> str:
        return f"output {index}\n" + "\x01" * 12_000 + "\nDONE"

    ledger = _ledger("codex", outputs=8, edits_per_path=1, output_text=noisy)
    unplanned = semantic_case_module._build_semantic_case_once(  # pyright: ignore[reportPrivateUsage]
        case_id="cas_10000000-0000-4000-8000-000000000001",
        frozen_case=ledger.case,
        dependency_digest="sha256:" + "b" * 64,
        findings=(),
        review_context_profile=ReviewContextProfile.EXPANDED,
        review_selection=_expanded_16(),
        policy_id="pvy_10000000-0000-4000-8000-000000000001",
        policy_version="1",
        lineage_evaluation=None,
        captured_content=ledger.captured,
        captured_content_scope=ledger.scope,
        captured_content_gaps=(),
        excerpt_byte_budget=None,
    )
    all_ids = {item.item_id for item in unplanned.items}
    assert len(semantic_case_to_prepared_payload(unplanned, all_ids)) > 262_144

    # The builder plans itself only below an explicit ceiling; the review composition passes the
    # channel-aware planner instead (#907 Phase 1b).
    semantic = _build(ledger, prepared_byte_ceiling=262_144)
    prepared = semantic_case_to_prepared_payload(
        semantic, {item.item_id for item in semantic.items}
    )
    assert len(prepared) <= 262_144 - 4_096
    assert "content_unselected" in semantic.packet.coverage.known_gaps
    # Reserved room survives the planning; only lower-ranked output is dropped.
    selected = {item.source_ref for item in semantic.items if item.section == "excerpt"}
    assert {str(ref) for ref in ledger.newest_edit_for_path.values()} <= selected
    dropped = {str(ref) for ref in ledger.outputs} - selected
    assert dropped
    assert all(
        any(omission.subject_ref == ref for omission in semantic.packet.omissions)
        for ref in dropped
    )


# --- Acceptance criterion 7: convergence ------------------------------------------------------


def test_next_packet_shows_the_prior_request_and_carries_the_item_supplied_since() -> None:
    """After the agent supplies a named item, the next review sees the request and the answer."""

    ledger = _ledger("claude", outputs=20, edits_per_path=2)
    pytest_runs = ledger.verification["pytest"]
    latest_run = pytest_runs[-1]
    run_frontier = ledger.case.projection.evidence[latest_run].source_frontier
    request = PendingMissingForAssessment(
        evt(run_frontier - 2),
        run_frontier - 2,
        (
            # The reviewer named the earlier failing run; a rerun of its command answers it.
            MissingForAssessmentItem(
                "verification_output", (str(pytest_runs[-2]),), "agent_suppliable"
            ),
            MissingForAssessmentItem(
                "command_identity", (), "structurally_unavailable_on_this_host"
            ),
        ),
    )
    case = replace(
        ledger.case,
        projection=replace(ledger.case.projection, pending_missing_for_assessment=request),
    )
    semantic = _build(replace(ledger, case=case))
    rows = {cast(str, row["item_id"]): row for row in _prepared_items(semantic)}

    prior = rows["prior-missing-for-assessment"]
    assert prior["section"] == "timeline" and prior["occurred_order"] == run_frontier - 2
    body = strict_json_parse(cast(str, prior["content"]).encode("utf-8"))
    assert isinstance(body, dict) and body["kind"] == "prior_missing_for_assessment"
    items = cast(list[dict[str, JsonValue]], body["items"])
    verification = next(item for item in items if item["kind"] == "verification_output")
    assert str(latest_run) in cast(list[str], verification["supplied_since"])
    assert verification["target_refs"] == [str(pytest_runs[-2])]
    # The ruff run recorded since is output of another command: it never answers this request.
    assert not {str(ref) for ref in ledger.verification["ruff"]} & set(
        cast(list[str], verification["supplied_since"])
    )
    # The supplied run itself travels in the reserved room, marked as the latest of its command.
    assert rows[f"excerpt-{latest_run}"]["latest_for"] == "command"
    assert "prior-missing-for-assessment" in semantic.packet.timeline_item_ids


@pytest.mark.parametrize("host", ["codex", "claude", "cursor"])
def test_a_fresh_git_diff_of_a_captured_path_is_supplied_for_that_capture(host: Host) -> None:
    """R940-01: a hook capture has no reference; the path its bytes record binds a fresh diff."""

    ledger = _ledger(host, outputs=4, edits_per_path=1)
    target = ledger.newest_edit_for_path[_PATHS[0]]
    helper_paths = captured_edit_paths(ledger.case, ledger.captured, ledger.scope)
    assert helper_paths[str(target)] == frozenset({_PATHS[0]})

    def supplied_for(diff_path: str, workspace_root: str | None = None) -> list[str]:
        action = ActionRecordedPayload(
            act(95), ActionKind.COMMAND, "Show the diff", command=f"git diff -- {diff_path}"
        )
        output = EvidenceRecordedPayload(
            evd(96),
            EvidenceKind.COMMAND_OUTPUT,
            EvidenceImmutability.METADATA_ONLY,
            timestamp_from_string("2026-09-27T00:00:00.000Z"),
            description="diff --git a/x b/x",
        )
        result = ResultRecordedPayload(
            res(97), act(95), ResultOutcome.SUCCESS, evidence_refs=(evd(96),)
        )
        projection = ledger.case.projection
        projection = replace(
            projection,
            actions={**projection.actions, act(95): record(action, 95)},
            evidence={**projection.evidence, evd(96): evidence_record(output, 96)},
            results={**projection.results, res(97): record(result, 97)},
            pending_missing_for_assessment=PendingMissingForAssessment(
                evt(90),
                90,
                (
                    MissingForAssessmentItem(
                        "current_diff_for_path", (str(target),), "agent_suppliable"
                    ),
                ),
            ),
        )
        added = cast(tuple[FindingBasisRef, ...], (act(95), evd(96), res(97)))
        case = replace(
            ledger.case,
            projection=projection,
            allowed_ids=ledger.case.allowed_ids | frozenset(added),
            coverage_by_ref={
                **ledger.case.coverage_by_ref,
                **{ref: ledger.case.coverage_by_ref[target] for ref in added},
            },
        )
        semantic = build_semantic_case(
            case_id="cas_10000000-0000-4000-8000-000000000001",
            frozen_case=case,
            dependency_digest="sha256:" + "b" * 64,
            findings=(),
            review_context_profile=ReviewContextProfile.EXPANDED,
            review_selection=_expanded_16(),
            policy_id="pvy_10000000-0000-4000-8000-000000000001",
            policy_version="1",
            captured_content=ledger.captured,
            captured_content_scope=ledger.scope,
            workspace_root=workspace_root,
        )
        rows = {cast(str, row["item_id"]): row for row in _prepared_items(semantic)}
        body = strict_json_parse(
            cast(str, rows["prior-missing-for-assessment"]["content"]).encode("utf-8")
        )
        assert isinstance(body, dict)
        (item,) = cast(list[dict[str, JsonValue]], body["items"])
        return cast(list[str], item["supplied_since"])

    assert supplied_for(f"./{_PATHS[0]}") == [str(evd(96))]
    assert supplied_for(_PATHS[1]) == []
    # An absolute path answers only inside the workspace root the review was given.
    assert supplied_for(f"/work/repo/{_PATHS[0]}", "/work/repo") == [str(evd(96))]
    assert supplied_for(f"/work/repo/{_PATHS[0]}") == []
    assert supplied_for(f"/other/repo/{_PATHS[0]}", "/work/repo") == []


def test_older_hunks_of_a_changed_path_are_not_starved_by_tool_output() -> None:
    """Captured edits are hunks: an older Edit of a file stays code under review (#883 rule)."""

    for host in ("codex", "claude", "cursor"):
        ledger = _ledger(host, outputs=20, edits_per_path=2)
        semantic = _build(ledger)
        items = {item.item_id: item for item in semantic.items}
        diffs = [
            items[row.excerpt_item_id]
            for row in semantic.packet.targeted_excerpts
            if items[row.excerpt_item_id].source_kind == "diff"
        ]
        assert len(diffs) == len(ledger.edit_path), host


def test_a_runs_own_output_is_never_superseded_by_its_own_failure_summary() -> None:
    evidence_ref, result_ref, action_ref = evd(11), res(12), act(10)
    case = make_case(
        claims={clm(1): record(ClaimRecordedPayload(clm(1), ClaimKind.COMPLETION, "done", ()), 3)},
        actions={
            action_ref: record(
                ActionRecordedPayload(action_ref, ActionKind.COMMAND, "Run", command="pytest -q"),
                10,
            )
        },
        evidence={
            evidence_ref: evidence_record(
                EvidenceRecordedPayload(
                    evidence_ref,
                    EvidenceKind.TEST_RESULT,
                    EvidenceImmutability.METADATA_ONLY,
                    timestamp_from_string("2026-09-27T00:00:00.000Z"),
                    description="E KeyError\n1 failed in 0.2s",
                ),
                11,
            )
        },
        results={
            result_ref: record(
                ResultRecordedPayload(
                    result_ref,
                    action_ref,
                    ResultOutcome.FAILURE,
                    1,
                    evidence_refs=(evidence_ref,),
                    summary="pytest failed: KeyError",
                ),
                12,
            )
        },
        extra_refs=(clm(1),),
    )
    semantic = build_semantic_case(
        case_id="cas_10000000-0000-4000-8000-000000000001",
        frozen_case=case,
        dependency_digest="sha256:" + "b" * 64,
        findings=(),
        review_context_profile=ReviewContextProfile.EXPANDED,
        review_selection=_expanded_16(),
        policy_id="pvy_10000000-0000-4000-8000-000000000001",
        policy_version="1",
    )
    items = {item.item_id: item for item in semantic.items}
    assert items[f"excerpt-{evidence_ref}"].superseded_by == ()
    assert items[f"excerpt-{evidence_ref}"].latest_for == "command"
    assert items[f"excerpt-fail-{result_ref}"].latest_for == "command"


def test_excerpt_selection_plans_below_the_owner_channel_ceiling_when_it_is_narrower() -> None:
    """An owner byte or token ceiling below the schema maximum drops excerpts, not the review.

    The gateway blocks a prepared packet over the policy's own ``max_bytes`` (or ``max_tokens``
    at four bytes per token); planning against the narrower ceiling keeps the reserved room and
    discloses the rest as ``content_unselected`` instead of a whole-review policy denial.
    """

    def large(index: int) -> str:
        return f"out {index}\n" + "x" * 6_000

    ledger = _ledger("codex", outputs=8, edits_per_path=1, output_text=large)
    wide = _build(ledger)
    wide_bytes = len(semantic_case_to_prepared_payload(wide, {item.item_id for item in wide.items}))
    ceiling = wide_bytes - 3 * 6_000
    narrow = _build(ledger, prepared_byte_ceiling=ceiling)
    prepared = semantic_case_to_prepared_payload(narrow, {item.item_id for item in narrow.items})
    # The planning reserve holds below a narrower owner ceiling too: marker growth of up to the
    # reserve after planning (privacy redaction markers differ in length) still fits.
    reserve = semantic_case_module._PLANNING_RESERVE_BYTES  # pyright: ignore[reportPrivateUsage]
    assert len(prepared) + reserve <= ceiling
    assert "content_unselected" in narrow.packet.coverage.known_gaps

    def excerpt_bytes(case: SemanticCase) -> int:
        return sum(item.content_bytes for item in case.items if item.section == "excerpt")

    assert excerpt_bytes(narrow) < excerpt_bytes(wide)
    selected = {item.source_ref for item in narrow.items if item.section == "excerpt"}
    assert {str(ref) for ref in ledger.newest_edit_for_path.values()} <= selected
    # A ceiling inside the reserve plans no excerpt at all; the gateway still decides the rest.
    starved = _build(ledger, prepared_byte_ceiling=reserve)
    assert not [item for item in starved.items if item.section == "excerpt"]
    with pytest.raises(ValueError, match="semantic_case_prepared_ceiling_invalid"):
        _build(ledger, prepared_byte_ceiling=0)


def test_full_excerpts_never_crowd_the_prior_findings_section_out() -> None:
    """#905 x #907: earlier AI findings take leftover case capacity after excerpts.

    Excerpts now fill the approved 16 KiB per slot and planning trims them to fit the prepared
    document, never the dialogue: every open AI finding the section can hold is still carried,
    so no finding is left unassessed (``reviewer_assessment_incomplete``) by excerpt pressure.
    """

    from unit.application.test_semantic_case_prior_findings import (
        _CHALLENGE,  # pyright: ignore[reportPrivateUsage]
        _semantic,  # pyright: ignore[reportPrivateUsage]
    )

    def large(index: int) -> str:
        return f"output {index}\n" + "x" * 16_000 + "\nDONE"

    open_findings = {
        fnd(number): finding_record(_semantic(number, challenge=_CHALLENGE), 80 + number)
        for number in range(1, MAX_PRIOR_FINDINGS + 1)
    }
    ledger = _ledger(
        "codex", outputs=24, edits_per_path=1, output_text=large, findings=open_findings
    )
    semantic = _build(ledger)
    excerpt_bytes = sum(item.content_bytes for item in semantic.items if item.section == "excerpt")
    assert excerpt_bytes > 64 * 1024
    carried = {item.source_ref for item in semantic.items if item.section == "prior_finding"}
    assert carried == {str(ref) for ref in open_findings}
    assert SEMANTIC_PRIOR_FINDINGS_OVER_LIMIT_GAP not in semantic.packet.coverage.known_gaps


def _ledger_evidence_case(count: int) -> tuple[DeterministicCase, tuple[EvidenceId, ...]]:
    """``count`` small ledger-evidence rows (never captured content), all supporting one claim."""

    refs = tuple(evd(number) for number in range(1, count + 1))
    evidence = {
        ref: evidence_record(
            EvidenceRecordedPayload(
                ref,
                EvidenceKind.TEST_RESULT,
                EvidenceImmutability.METADATA_ONLY,
                timestamp_from_string("2026-09-27T00:00:00.000Z"),
                description=f"run {number}: 12 passed",
            ),
            number,
        )
        for number, ref in enumerate(refs, start=1)
    }
    claim = record(ClaimRecordedPayload(clm(1), ClaimKind.COMPLETION, "Lookups repaired", refs), 99)
    return make_case(evidence=evidence, claims={clm(1): claim}, extra_refs=(clm(1),)), refs


def _build_case(
    case: DeterministicCase, profile: ReviewContextProfile, selection: ReviewSelectionPolicy
) -> SemanticCase:
    return build_semantic_case(
        case_id="cas_10000000-0000-4000-8000-000000000001",
        frozen_case=case,
        dependency_digest="sha256:" + "b" * 64,
        findings=(),
        review_context_profile=profile,
        review_selection=selection,
        policy_id="pvy_10000000-0000-4000-8000-000000000001",
        policy_version="1",
    )


@pytest.mark.parametrize("profile", [ReviewContextProfile.ASSISTED, ReviewContextProfile.EXPANDED])
def test_ledger_excerpts_the_count_cap_cuts_are_disclosed(profile: ReviewContextProfile) -> None:
    """Every ledger excerpt the 16-slot count cuts is an omission and discloses the gap."""

    case, refs = _ledger_evidence_case(40)
    semantic = _build_case(
        case, profile, replace(ReviewSelectionPolicy.for_profile(profile), max_excerpts=16)
    )
    shown = {item.source_ref for item in semantic.items if item.section == "excerpt"}
    assert len(shown) == 16
    cut = {
        omission.subject_ref
        for omission in semantic.packet.omissions
        if omission.reason == "not_selected" and omission.subject_ref.startswith("evd_")
    }
    assert len(cut) == 24
    assert cut | shown == {str(ref) for ref in refs}
    assert "content_unselected" in semantic.packet.coverage.known_gaps


def test_past_the_omission_cap_the_gap_is_the_trace() -> None:
    case, _refs = _ledger_evidence_case(40)
    selection = replace(_expanded_16(), max_omissions=4)
    semantic = _build_case(case, ReviewContextProfile.CUSTOM, selection)
    assert len(semantic.packet.omissions) <= 4
    assert "content_unselected" in semantic.packet.coverage.known_gaps


def test_the_manifest_reports_the_true_omission_total_past_the_listed_cap() -> None:
    """Issue #976 (tb4n1 D11): the listed count saturates at 64; the total is the real count."""

    refs = tuple(evd(number) for number in range(1, 91))
    evidence = {
        ref: evidence_record(
            EvidenceRecordedPayload(
                ref,
                EvidenceKind.TEST_RESULT,
                EvidenceImmutability.METADATA_ONLY,
                timestamp_from_string("2026-09-27T00:00:00.000Z"),
                description=f"run {number}: 12 passed",
            ),
            number,
        )
        for number, ref in enumerate(refs, start=1)
    }
    claim = record(
        ClaimRecordedPayload(clm(1), ClaimKind.COMPLETION, "Lookups repaired", refs[:64]), 99
    )
    case = make_case(evidence=evidence, claims={clm(1): claim}, extra_refs=(clm(1),))
    semantic = _build_case(case, ReviewContextProfile.EXPANDED, _expanded_16())

    manifest = semantic.packet.input_manifest
    assert manifest is not None
    assert len(semantic.packet.omissions) == manifest.omitted_item_count == 64
    assert manifest.omitted_item_total is not None
    assert manifest.omitted_item_total >= len(refs) - 16 > 64
    encoded = review_input_manifest_to_json(manifest)
    assert encoded["omitted_item_total"] == manifest.omitted_item_total
    # The provider-bound projection carries it, and the disclosure check re-derives it exactly.
    content_by_id = {item.item_id: item.content for item in semantic.items}
    prepared = assemble_filtered_review_packet(
        cast(dict[str, JsonValue], strict_json_parse(bounded_case_envelope(semantic))),
        content_by_id=content_by_id,
        included_item_ids=set(content_by_id),
    )
    result = review_packet_disclosure_result(prepared)
    assert result.failure is None
    assert result.disclosure is not None
    provider = result.disclosure.provider_input_manifest
    assert provider is not None
    assert provider["omitted_item_count"] == 64
    assert provider["omitted_item_total"] == manifest.omitted_item_total
    # Below the cap the two agree.
    small, _ = _ledger_evidence_case(20)
    below = _build_case(small, ReviewContextProfile.EXPANDED, _expanded_16()).packet
    assert below.input_manifest is not None
    assert below.input_manifest.omitted_item_total == below.input_manifest.omitted_item_count
    assert below.input_manifest.omitted_item_count == len(below.omissions)


def test_relevance_exclusion_is_a_policy_choice_not_a_budget_cut() -> None:
    """Assisted carries linked subjects only: unlinked ledger evidence is ``not_selected`` by
    policy, which the omission rows state, and is not a budget cut (no ``content_unselected``)."""

    refs = tuple(evd(number) for number in range(1, 5))
    evidence = {
        ref: evidence_record(
            EvidenceRecordedPayload(
                ref,
                EvidenceKind.TEST_RESULT,
                EvidenceImmutability.METADATA_ONLY,
                timestamp_from_string("2026-09-27T00:00:00.000Z"),
                description="12 passed",
            ),
            number,
        )
        for number, ref in enumerate(refs, start=1)
    }
    profile = ReviewContextProfile.ASSISTED
    semantic = _build_case(
        make_case(evidence=evidence), profile, ReviewSelectionPolicy.for_profile(profile)
    )
    assert not [item for item in semantic.items if item.section == "excerpt"]
    assert {o.subject_ref for o in semantic.packet.omissions if o.reason == "not_selected"} >= {
        str(ref) for ref in refs
    }
    assert "content_unselected" not in semantic.packet.coverage.known_gaps


def _assert_count_cut_disclosed(semantic: SemanticCase, refs: tuple[str, ...]) -> None:
    shown = {item.source_ref for item in semantic.items if item.section == "excerpt"}
    assert len(shown) == 16
    cut = {
        omission.subject_ref
        for omission in semantic.packet.omissions
        if omission.reason == "not_selected" and omission.subject_ref in refs
    }
    assert len(cut) == 24
    assert cut | shown == set(refs)
    assert "content_unselected" in semantic.packet.coverage.known_gaps


def test_command_excerpts_the_count_cap_cuts_are_disclosed() -> None:
    """The exact-command candidates compete in the same admission loop and disclose their cut."""

    actions = {
        act(number): record(
            ActionRecordedPayload(
                act(number), ActionKind.COMMAND, f"run {number}", command=f"pytest -k case_{number}"
            ),
            number,
        )
        for number in range(1, 41)
    }
    profile = ReviewContextProfile.EXPANDED
    semantic = _build_case(
        make_case(actions=actions),
        profile,
        replace(ReviewSelectionPolicy.for_profile(profile), max_excerpts=16),
    )
    _assert_count_cut_disclosed(semantic, tuple(str(ref) for ref in actions))


def test_failure_excerpts_the_count_cap_cuts_are_disclosed() -> None:
    """Failed-result summaries compete in the same admission loop and disclose their cut."""

    actions = {
        act(number): record(ActionRecordedPayload(act(number), ActionKind.EDIT, "edit"), number)
        for number in range(1, 41)
    }
    results = {
        res(number): record(
            ResultRecordedPayload(
                res(number), act(number), ResultOutcome.FAILURE, summary=f"case {number} failed"
            ),
            40 + number,
        )
        for number in range(1, 41)
    }
    profile = ReviewContextProfile.EXPANDED
    semantic = _build_case(
        make_case(actions=actions, results=results),
        profile,
        replace(ReviewSelectionPolicy.for_profile(profile), max_excerpts=16),
    )
    _assert_count_cut_disclosed(semantic, tuple(str(ref) for ref in results))
