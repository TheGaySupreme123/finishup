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
from builders.start_application import protocol_id
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
        key=protocol_id("evt_", 9000),
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
        key=protocol_id("evt_", 9001),
        values=values,
        scope=scope,
        boundary="task_start",
        clock=FixedClock(),
        request_id=None,
    )
    later = await record_input_snapshot(
        runtime=runtime,
        key=protocol_id("evt_", 9002),
        values=(f"{root}/d.md", f"{root}/e.md", f"{root}/spec.md"),
        scope=scope,
        boundary="admission_time",
        clock=FixedClock(),
        request_id=None,
    )
    exhausted = await record_input_snapshot(
        runtime=runtime,
        key=protocol_id("evt_", 9003),
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
        key=protocol_id("evt_", 9004),
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
        "task_start", (SnapshotFile(spec, root, _ORIGINAL, len(_ORIGINAL)),)
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


# Review R1-R6 (#1118 unit 1 fix round 1).


def _files(root: Path, count: int) -> tuple[str, ...]:
    for index in range(count):
        (root / f"spec{index}.md").write_bytes(f"GT_ZERO_{index}\n".encode())
    return tuple(os.fspath(root / f"spec{index}.md") for index in range(count))


async def _record(runtime: Any, seed: int, values: tuple[str, ...], scope: Any) -> bool:
    return await record_input_snapshot(
        runtime=runtime,
        key=protocol_id("req_", seed),
        values=values,
        scope=scope,
        boundary="admission_time",
        clock=FixedClock(),
        request_id=None,
    )


@pytest.mark.anyio
@pytest.mark.parametrize("ledger", ["memory", "sqlite"])
async def test_a_reserved_boundary_is_never_read_again(
    shared: Path, tmp_path: Path, ledger: str
) -> None:
    """R1: the second attempt at one boundary, even after a crash left it reserved, reads nothing."""

    runtime = _runtime(ledger)
    calls: list[int] = []

    def reader(*args: Any, **kwargs: Any) -> Any:
        calls.append(1)
        return snapshot_outside_inputs(*args, **kwargs)

    scope = InputSnapshotScope((os.fspath(shared),), (), reader)
    spec = (os.fspath(shared / "spec.md"),)
    assert await _record(runtime, 9100, spec, scope)
    (shared / "spec.md").write_bytes(_REWRITTEN)
    assert not await _record(runtime, 9100, spec, scope)
    # A crash after the reservation and before its completion: the boundary is spent.
    assert await runtime.ledger.reserve_task_input_snapshot(protocol_id("req_", 9101)) is not None
    assert not await _record(runtime, 9101, spec, scope)

    assert len(calls) == 1
    ((kept,),) = [s.files for s in await load_input_snapshots(runtime, None)]
    assert kept.text == _ORIGINAL


@pytest.mark.anyio
@pytest.mark.parametrize("ledger", ["memory", "sqlite"])
async def test_concurrent_admissions_share_the_task_file_budget(
    tmp_path: Path, ledger: str
) -> None:
    """R3: an admission reserves capacity in the ledger before it reads, so two admissions in
    flight together never keep more than four files between them."""

    import asyncio  # noqa: PLC0415
    import threading  # noqa: PLC0415

    root = (tmp_path / "shared").resolve()
    root.mkdir()
    values = _files(root, 8)
    runtime = _runtime(ledger)
    entered, release = threading.Event(), threading.Event()

    def held(*args: Any, **kwargs: Any) -> Any:
        entered.set()
        assert release.wait(timeout=30)
        return snapshot_outside_inputs(*args, **kwargs)

    first = asyncio.ensure_future(
        _record(runtime, 9200, values[:4], InputSnapshotScope((os.fspath(root),), (), held))
    )
    # The first admission has reserved and is reading; the second runs to completion meanwhile.
    assert await asyncio.to_thread(entered.wait, 30)
    second = await _record(runtime, 9201, values[4:], _scope(root, tmp_path / "repo"))
    release.set()
    assert await first and second

    snapshots = await load_input_snapshots(runtime, None)
    assert sum(len(s.files) for s in snapshots) == 4
    assert {reason for s in snapshots for _path, reason in s.omitted} == {"budget"}


@pytest.mark.anyio
async def test_directory_members_count_as_candidates(tmp_path: Path) -> None:
    """R3: each member a declared directory expands to is one of the task's 16 candidates."""

    root = (tmp_path / "shared").resolve()
    root.mkdir()
    runtime = _runtime("memory")
    for seed, folder in enumerate(("a", "b")):
        directory = root / folder
        directory.mkdir()
        for index in range(12):
            (directory / f"binary{index:02d}.txt").write_bytes(b"\x00not_text")
        await _record(runtime, 9300 + seed, (f"{directory}/",), _scope(root, tmp_path / "repo"))

    snapshots = await load_input_snapshots(runtime, None)
    assert [len(s.omitted) for s in snapshots] == [12, 4]
    grant = await runtime.ledger.reserve_task_input_snapshot(protocol_id("req_", 9302))
    assert grant is not None and grant.candidates == 0


@pytest.mark.anyio
async def test_captures_that_keep_nothing_still_spend_time(
    shared: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R3: three four-second admissions that kept nothing leave two seconds for the third."""

    import finishup.application.input_snapshot as module  # noqa: PLC0415

    runtime = _runtime("memory")
    now = 0.0
    limits: list[float] = []

    def reader(*_args: Any, **kwargs: Any) -> tuple[()]:
        nonlocal now
        limits.append(kwargs["seconds"])
        now += 4.0
        return ()

    monkeypatch.setattr(module, "time", SimpleNamespace(monotonic=lambda: now))
    scope = InputSnapshotScope((os.fspath(shared),), (), reader)
    for seed in range(3):
        assert not await _record(runtime, 9400 + seed, (os.fspath(shared / "spec.md"),), scope)

    assert limits == [5.0, 5.0, 2.0]


@pytest.mark.anyio
async def test_an_unreadable_earlier_set_stops_capture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R3: an earlier set that cannot be read stops the capture; it never refills the budget."""

    import finishup.application.input_snapshot as module  # noqa: PLC0415

    root = (tmp_path / "shared").resolve()
    root.mkdir()
    values = _files(root, 8)
    runtime = _runtime("memory")
    scope = _scope(root, tmp_path / "repo")
    assert await _record(runtime, 9500, values[:4], scope)

    async def unreadable(*_args: object) -> bytes:
        raise OSError("simulated_snapshot_read_failure")

    with monkeypatch.context() as patch:
        patch.setattr(module, "_read", unreadable)
        assert not await _record(runtime, 9501, values[4:], scope)
    await _record(runtime, 9502, values[4:], scope)  # Once readable again: budget only.

    assert sum(len(s.files) for s in await load_input_snapshots(runtime, None)) == 4


@pytest.mark.parametrize("restriction", ["local_only", "no_repository_excerpts", "local_model"])
def test_snapshots_follow_the_owner_review_and_file_controls(restriction: str) -> None:
    """R2: no read ahead for a review the owner turned off or a file category withheld; a
    separately enabled local model that admits excerpts still may."""

    from finishup.domain.privacy import (  # noqa: PLC0415
        ConversationReview,
        DataCategory,
        DataClass,
    )

    excerpt = DataCategory.REPOSITORY_EXCERPT
    policy = replace(minimal_external_policy(), admitted_input_roots=("/shared",))
    assert snapshot_roots(policy, carries_task_inputs=True) == ("/shared",)
    if restriction == "local_only":
        policy = replace(policy, conversation_review=ConversationReview.LOCAL_ONLY)
    else:
        policy = replace(
            policy,
            channel_policies=tuple(
                replace(
                    channel,
                    allowed_categories=tuple(c for c in channel.allowed_categories if c != excerpt),
                )
                for channel in policy.channel_policies
            ),
        )
    assert snapshot_roots(policy, carries_task_inputs=True) == ()
    if restriction == "local_model":
        from integration.privacy.test_egress_gateway import (  # noqa: PLC0415
            _policy,  # pyright: ignore[reportPrivateUsage]
        )

        local = replace(
            _policy(external_enabled=False, local_enabled=True),
            admitted_input_roots=("/shared",),
            local_model_categories=(excerpt,),
            local_model_data_classes=(DataClass.ORDINARY_USER_CONTENT,),
            conversation_review=ConversationReview.LOCAL_AGENT_OPT_IN,
        )
        assert snapshot_roots(local, carries_task_inputs=True) == ("/shared",)
        assert snapshot_roots(replace(local, local_model_categories=()), True) == ()


def test_equality_after_redaction_is_not_called_equality_of_the_file(tmp_path: Path) -> None:
    """R5: two different secrets redact alike; the label never says the file still matches."""

    from finishup.application.check_change import (  # noqa: PLC0415
        _redacted_text,  # pyright: ignore[reportPrivateUsage]
        _snapshot_inputs,  # pyright: ignore[reportPrivateUsage]
    )

    before = b'password="first-secret-value-123456789"\n'
    after = b'password="second-secret-value-987654321"\n'
    kept, redacted = _redacted_text(before)
    assert redacted and _redacted_text(after)[0] == kept
    path = "/shared/spec.txt"
    snapshot = TaskInputSnapshotSet(
        "task_start", (SnapshotFile(path, "/shared", kept, len(before), True),)
    )
    (item,) = _snapshot_inputs(
        (snapshot,), (path,), ("/shared",), lambda paths: {paths[0]: after}, set(), 4
    )
    label, _cut = _task_input_text(item)
    assert "still matches it" not in label
    assert "outside its redacted values; whether those values changed is unknown" in label
    assert "were redacted from this copy" in label


@pytest.mark.parametrize("mutation", ["replace_path", "group_writable"])
def test_a_file_replaced_or_loosened_during_its_read_is_not_kept(
    shared: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    """R6: the name must still lead to the file read, with unchanged owner, mode and ctime."""

    import finishup.adapters.task_input_read as module  # noqa: PLC0415

    spec = shared / "spec.md"
    original_read = os.read
    mutated = False

    def read_then_mutate(descriptor: int, count: int) -> bytes:
        nonlocal mutated
        content = original_read(descriptor, count)
        if not mutated:
            mutated = True
            if mutation == "replace_path":
                (shared / "replacement.md").write_bytes(_REWRITTEN)
                os.replace(shared / "replacement.md", spec)
            else:
                os.chmod(spec, 0o660)
        return content

    monkeypatch.setattr(module.os, "read", read_then_mutate)
    rows = snapshot_outside_inputs(
        (os.fspath(shared),), (os.fspath(spec),), limit=4, max_bytes=256 * 1024, seconds=5
    )
    assert [(row.text, row.reason) for row in rows] == [(None, "unreadable")]


@pytest.mark.parametrize("state", ["same", "changed", "unavailable", "none"])
def test_plain_snapshot_labels_distinguish_current_states(state: str) -> None:
    from finishup.application.check_change import (  # noqa: PLC0415
        _snapshot_inputs,  # pyright: ignore[reportPrivateUsage]
    )

    path = "/shared/spec.txt"
    snapshot = TaskInputSnapshotSet(
        "task_start", (SnapshotFile(path, "/shared", _ORIGINAL, len(_ORIGINAL)),)
    )
    if state == "none":
        item = TaskInputFile(
            path, _REWRITTEN, len(_REWRITTEN), origin="outside_workspace", root="/shared"
        )
    else:
        current = (
            {} if state == "unavailable" else {path: _ORIGINAL if state == "same" else _REWRITTEN}
        )
        (item,) = _snapshot_inputs((snapshot,), (path,), ("/shared",), lambda _: current, set(), 4)
        assert item.current_state == state and item.text == _ORIGINAL
    label, _cut = _task_input_text(item)
    expected = {
        "same": "still matches it",
        "changed": "has changed since that copy",
        "unavailable": "could not be read",
        "none": "its current bytes",
    }[state]
    assert expected in label and "not the agent's work" not in label
    assert "redacted" not in label


@pytest.mark.anyio
async def test_a_kept_copy_is_redacted_and_the_ledger_row_is_structural(shared: Path) -> None:
    raw = b'password="example-secret-value-123456789"\n'
    (shared / "spec.md").write_bytes(raw)
    runtime = _runtime("sqlite")
    scope = InputSnapshotScope((os.fspath(shared),), (), snapshot_outside_inputs)
    assert await _record(runtime, 9600, (os.fspath(shared / "spec.md"),), scope)
    ((item,),) = [s.files for s in await load_input_snapshots(runtime, None)]
    assert item.redacted and raw not in item.text
    rows = runtime.ledger._db.execute(  # pyright: ignore[reportUnknownMemberType]
        "SELECT value FROM bundle_meta WHERE key='task_input_snapshots'"
    ).fetchall()
    assert os.fspath(shared) not in str(rows) and "example-secret-value" not in str(rows)
