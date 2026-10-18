"""#1118 unit 1: task-input snapshots (AIP-1) and outside-root bindings at egress (E2E-2)."""

from __future__ import annotations

import os
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from builders.ledger_adapters import FixedClock, append_command, memory_adapter, sqlite_adapter
from builders.privacy_policies import INSTALLATION_ID, minimal_external_policy
from finishup.adapters.privacy.local_enforcer import LocalPrivacyEnforcer
from finishup.adapters.task_input_read import snapshot_outside_inputs
from finishup.application.check_change import (
    _with_outside_inputs,  # pyright: ignore[reportPrivateUsage]
)
from finishup.application.egress import PrivacyCoordinator
from finishup.application.input_snapshot import (
    InputSnapshotScope,
    load_input_snapshots,
    record_input_snapshot,
    snapshot_roots,
)
from finishup.application.semantic_case import (
    _task_input_text,  # pyright: ignore[reportPrivateUsage]
    semantic_case_to_candidate_context,
)
from finishup.domain.privacy import (
    AuthorizationScope,
    AuthorizationScopeKind,
    EgressChannel,
)
from finishup.ports.change_capture import (
    CheckChangeCapture,
    SnapshotFile,
    TaskInputFile,
    TaskInputSnapshotSet,
    decode_check_change,
    decode_task_input_snapshot,
    encode_check_change,
    encode_task_input_snapshot,
)
from finishup.ports.privacy import EffectivePrivacyPolicy

_ORIGINAL = b"OWNER_SPEC_THRESHOLD_GT_ZERO\n"
_REWRITTEN = b"AGENT_REPLACED_SPEC_THRESHOLD_GE_ZERO\n"


@pytest.fixture
def shared(tmp_path: Path) -> Path:
    root = (tmp_path / "shared").resolve()
    root.mkdir()
    (root / "spec.md").write_bytes(_ORIGINAL)
    return root


def _runtime(kind: str) -> Any:
    command = append_command()
    ledger = memory_adapter(command) if kind == "memory" else sqlite_adapter(command)
    return SimpleNamespace(
        task_id=command.task_id,
        ledger=ledger,
        objects=getattr(ledger, "_objects"),
    )


def _scope(root: Path, workspace: Path) -> InputSnapshotScope:
    return InputSnapshotScope((os.fspath(root),), (os.fspath(workspace),), snapshot_outside_inputs)


def _current(root: str) -> Any:
    def read(paths: tuple[str, ...]) -> dict[str, bytes | None]:
        rows = snapshot_outside_inputs(
            (root,), paths, limit=len(paths), max_bytes=256 * 1024, seconds=5.0
        )
        return {row.path: row.text for row in rows if row.reason != "unreadable"}

    return read


def _no_current_reads(*_: object) -> tuple[TaskInputFile, ...]:
    return ()


def _empty_capture() -> CheckChangeCapture:
    return CheckChangeCapture("task_start", b"diff --git a/x b/x\n", 1, 0, 0, False, False)


@pytest.mark.anyio
@pytest.mark.parametrize("ledger", ["memory", "sqlite"])
async def test_a_spec_rewritten_after_start_reaches_review_as_the_start_copy(
    shared: Path, tmp_path: Path, ledger: str
) -> None:
    """AIP-1: the agent's rewrite cannot pose as the original specification."""

    runtime = _runtime(ledger)
    spec = os.fspath(shared / "spec.md")
    kept = await record_input_snapshot(
        runtime=runtime,
        values=(spec, "docs/inside.md"),
        scope=_scope(shared, tmp_path / "repo"),
        boundary="task_start",
        clock=FixedClock(),
        request_id=None,
    )
    assert kept is True
    (shared / "spec.md").write_bytes(_REWRITTEN)

    snapshots = await load_input_snapshots(runtime, None)
    capture = _with_outside_inputs(
        _empty_capture(),
        (spec,),
        _no_current_reads,
        os.fspath(tmp_path / "repo"),
        verification_paths=frozenset(),
        snapshots=snapshots,
        admitted_roots=(os.fspath(shared),),
        current_reader=_current(os.fspath(shared)),
    )

    (item,) = capture.inputs
    assert item.text == _ORIGINAL and item.root == os.fspath(shared)
    assert (item.baseline, item.current_state) == ("task_start", "changed")
    label, _cut = _task_input_text(item)
    assert "the copy FinishUP kept before the task's start returned" in label
    assert "has changed since that copy" in label and "not the agent's work" not in label
    assert _REWRITTEN.decode() not in label
    # The binding and the baseline survive the encrypted check-change object.
    assert decode_check_change(encode_check_change(capture)) == capture


@pytest.mark.anyio
async def test_bounds_are_task_wide_and_never_replenished(shared: Path, tmp_path: Path) -> None:
    runtime = _runtime("memory")
    for name in ("a.md", "b.md", "c.md", "d.md", "e.md"):
        (shared / name).write_text(f"{name}\n", encoding="utf-8")
    (shared / "big.md").write_bytes(b"x" * (256 * 1024 + 1))
    (shared / "blob.bin").write_bytes(b"\0\1\2binary")
    root = os.fspath(shared)
    values = tuple(f"{root}/{name}" for name in ("big.md", "blob.bin", "a.md", "b.md", "c.md"))
    scope = _scope(shared, tmp_path / "repo")

    first = await record_input_snapshot(
        runtime=runtime,
        values=values,
        scope=scope,
        boundary="task_start",
        clock=FixedClock(),
        request_id=None,
    )
    later = await record_input_snapshot(
        runtime=runtime,
        values=(f"{root}/d.md", f"{root}/e.md", f"{root}/spec.md"),
        scope=scope,
        boundary="admission_time",
        clock=FixedClock(),
        request_id=None,
    )
    exhausted = await record_input_snapshot(
        runtime=runtime,
        values=(f"{root}/e.md",),
        scope=scope,
        boundary="admission_time",
        clock=FixedClock(),
        request_id=None,
    )

    assert (first, later, exhausted) == (True, True, False)
    start, admitted = await load_input_snapshots(runtime, None)
    assert start.boundary == "task_start" and admitted.boundary == "admission_time"
    assert [Path(item.path).name for item in start.files] == ["a.md", "b.md", "c.md"]
    assert dict((Path(p).name, r) for p, r in start.omitted) == {
        "big.md": "too_large",
        "blob.bin": "not_text",
    }
    # Four whole files across the task: the later declaration got only the one left.
    assert [Path(item.path).name for item in admitted.files] == ["d.md"]


@pytest.mark.anyio
async def test_no_admitted_root_or_no_review_reads_nothing(shared: Path, tmp_path: Path) -> None:
    runtime = _runtime("memory")
    empty = InputSnapshotScope((), (os.fspath(tmp_path),), snapshot_outside_inputs)

    assert not await record_input_snapshot(
        runtime=runtime,
        values=(os.fspath(shared / "spec.md"),),
        scope=empty,
        boundary="task_start",
        clock=FixedClock(),
        request_id=None,
    )
    assert await load_input_snapshots(runtime, None) == ()
    policy = replace(minimal_external_policy(), admitted_input_roots=(os.fspath(shared),))
    assert snapshot_roots(policy, carries_task_inputs=False) == ()
    assert snapshot_roots(policy, carries_task_inputs=True) == (os.fspath(shared),)


def test_a_removed_root_withdraws_its_snapshot_and_unbound_bytes_are_labelled_current(
    shared: Path, tmp_path: Path
) -> None:
    root = os.fspath(shared)
    spec = f"{root}/spec.md"
    snapshot = TaskInputSnapshotSet(
        "task_start", 1, 0, (SnapshotFile(spec, root, _ORIGINAL, len(_ORIGINAL)),)
    )
    assert decode_task_input_snapshot(encode_task_input_snapshot(snapshot)) == snapshot

    def current(*_: object) -> tuple[TaskInputFile, ...]:
        return (TaskInputFile(spec, _REWRITTEN, len(_REWRITTEN), origin="outside_workspace"),)

    capture = _with_outside_inputs(
        _empty_capture(),
        (spec,),
        current,
        os.fspath(tmp_path / "repo"),
        verification_paths=frozenset(),
        snapshots=(snapshot,),
        admitted_roots=(),
    )

    (item,) = capture.inputs
    assert item.baseline == "current" and item.text == _REWRITTEN
    label, _cut = _task_input_text(item)
    assert "is unverified]" in label and "not the agent's work" not in label


def _decision(root: str, admitted: tuple[str, ...]) -> tuple[bool, bool]:
    """The supply probe (E2E-2): bytes read beneath ``root`` under the policy admitting
    ``admitted``. Returns whether the item was approved and reached the prepared bytes."""

    from unit.application.test_semantic_case_packet_completeness import (  # noqa: PLC0415
        _build,  # pyright: ignore[reportPrivateUsage]
        _change,  # pyright: ignore[reportPrivateUsage]
        _statement_case,  # pyright: ignore[reportPrivateUsage]
    )

    marker = b"OUTSIDE_INPUT_AFTER_REVOCATION"
    item = TaskInputFile(
        f"{root}/spec.txt", marker, len(marker), origin="outside_workspace", root=root
    )
    case = _build(_statement_case(), change=_change(inputs=(item,)))
    policy = replace(minimal_external_policy(), admitted_input_roots=admitted)
    binding = next(
        channel.provider_binding
        for channel in policy.channel_policies
        if channel.channel is EgressChannel.LLM_INFERENCE
    )
    assert binding is not None
    scope = AuthorizationScope(
        AuthorizationScopeKind.TASK,
        INSTALLATION_ID,
        "hmac-sha256:" + "f" * 64,
        "tsk_10000000-0000-4000-8000-000000000001",
    )
    candidate = semantic_case_to_candidate_context(
        case,
        request_id="req_10000000-0000-4000-8000-000000000001",
        scope=scope,
        provider_binding=binding,
    )
    effective = EffectivePrivacyPolicy(policy, 2, policy.policy_digest)
    enforcer = LocalPrivacyEnforcer()
    classified = enforcer.classify(candidate, effective)
    coordinator = object.__new__(PrivacyCoordinator)
    decision = getattr(coordinator, "_semantic_decision")(classified, effective, binding)
    minimized = enforcer.minimize_and_scan(classified, decision)
    return "task-input-01" in decision.approved_item_ids, marker in minimized.prepared_bytes


def test_bytes_read_beneath_a_removed_root_are_refused_at_admission() -> None:
    """E2E-2 reproduction: the root was removed after capture and before admission."""

    assert _decision("/shared", admitted=()) == (False, False)
    # Control: while the root stays admitted the same bytes are approved.
    assert _decision("/shared", admitted=("/shared",)) == (True, True)


def test_the_missing_baseline_is_disclosed_on_every_surface_without_a_path() -> None:
    """CLI, MCP and the receipt (JSON, markdown, text) say the outside input was current bytes."""

    from types import SimpleNamespace  # noqa: PLC0415

    from finishup.cli.render import render_human_check  # noqa: PLC0415
    from finishup.domain.receipts import (  # noqa: PLC0415
        TASK_INPUT_BASELINE_UNAVAILABLE_GAP,
        check_time_change_gap_sentence,
        receipt_document_to_json,
        render_receipt_human,
    )
    from finishup.kernel.deterministic_checks import CaseGap  # noqa: PLC0415
    from finishup.mcp.summaries import summary_for_check  # noqa: PLC0415
    from finishup.protocol.models import CheckSuccessModel  # noqa: PLC0415
    from unit.kernel.test_receipt_builder import (  # noqa: PLC0415
        _build,  # pyright: ignore[reportPrivateUsage]
        _context,  # pyright: ignore[reportPrivateUsage]
        _coverage,  # pyright: ignore[reportPrivateUsage]
    )

    code = TASK_INPUT_BASELINE_UNAVAILABLE_GAP
    sentence = check_time_change_gap_sentence(code)
    assert sentence is not None and "could not tell whether the agent changed it" in sentence
    summary = summary_for_check(
        {"verdict": "insufficient_coverage", "coverage": {"known_gaps": [code]}}
    )
    assert sentence in summary and "/shared" not in summary
    check = CheckSuccessModel.model_construct(
        verdict="insufficient_coverage",
        semantic_status="succeeded",
        semantic_reason="semantic_completed",
        semantic_route_required=False,
        findings=(),
        review_mode=None,
        totals=None,
        observations_awaited=None,
        review_input_manifest=None,
        semantic_provenance=None,
        suppressed_count=0,
        coverage=SimpleNamespace(known_gaps=(code,)),
    )
    assert sentence in render_human_check(check)
    context = _context(
        coverage=replace(_coverage(), known_gaps=("check_not_recorded", code)),
        gaps=(
            CaseGap("check_not_recorded", "check_not_recorded", ()),
            CaseGap(code, code, ()),
        ),
    )
    receipt = _build(context)
    assert sentence in str(receipt_document_to_json(receipt))
    assert sentence in render_receipt_human(receipt, markdown=True)
    assert sentence in render_receipt_human(receipt, markdown=False)
