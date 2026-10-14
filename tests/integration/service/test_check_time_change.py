"""The check-time change reaches the review packet through the real composition (#883, ADR-031).

The repository is a real Git workspace edited the way the v2 benchmark's kea attempt did: shell
Python rewrites and a commit, with no native edit tool at all, so no observation capture exists.
The semantic evaluator, durable job ledger, object store, redaction and case builder are the
production ones; only the privacy coordinator is the recording fake from the non-dispatch suite.
"""

from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Awaitable, Callable
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest

import finishup.application.check as check_module
import finishup.observability.diagnostics as diagnostics_module
import finishup.service.ready_composition as ready_composition_module
import integration.service.test_semantic_non_dispatch as non_dispatch
from builders.ledger_adapters import (
    FixedClock,
    MemoryObjects,
    append_command,
    memory_adapter,
    sqlite_adapter,
)
from builders.policy_cases import (
    clm,
    make_case,
    obl,
    obligation_record,
    record,
)
from finishup.adapters.git_change_capture import GitChangeCaptureAdapter
from finishup.adapters.memory.ledger import MemoryLedgerAdapter
from finishup.adapters.privacy.local_enforcer import LocalPrivacyEnforcer, scan_exact_bytes
from finishup.adapters.sqlite.repository import SqliteLedger
from finishup.application.check import FinalSemanticEvaluation
from finishup.application.check_change import (
    capture_check_time_change,
    check_change_shown_files,
    record_task_change_base,
)
from finishup.application.egress import PrivacyCoordinator
from finishup.application.semantic_case import (
    CHECK_TIME_CHANGE_ITEM_PREFIX,
    REVIEW_PACKET_ITEM_ID,
    CheckTimeChange,
)
from finishup.domain.events import (
    CheckChangeShownFiles,
    ClaimKind,
    ClaimRecordedPayload,
    ObligationPublishedPayload,
    ObligationStatus,
)
from finishup.domain.privacy import (
    AuthorizationScopeKind,
    CandidateContext,
    ChannelPolicy,
    DataClass,
    EgressChannel,
    PrivacyOutcome,
    PrivacyProfile,
    PrivacyReason,
    ProviderBinding,
    ReviewContextProfile,
)
from finishup.domain.receipts import (
    CHECK_TIME_CHANGE_BASE_UNAVAILABLE_GAP,
    CHECK_TIME_CHANGE_REDACTED_GAP,
    CHECK_TIME_CHANGE_TRUNCATED_GAP,
    CHECK_TIME_CHANGE_UNAVAILABLE_GAP,
)
from finishup.ports.change_capture import (
    CHECK_CHANGE_MEDIA_TYPE,
    CheckChangeCapture,
    CheckWorkspaceSource,
    check_workspace_source_scope,
)
from finishup.ports.ledger import FrozenCase
from finishup.ports.objects import ObjectKind, ObjectMetadata, ObjectRef
from finishup.ports.privacy import EffectivePrivacyPolicy
from finishup.ports.runtime import TaskRuntime
from finishup.ports.start_catalog import StartCatalogPort
from finishup.protocol.canonical import strict_json_parse
from finishup.protocol.models import DataCategory, SemanticStatus

type _Evaluator = Callable[
    [FrozenCase, tuple[object, ...], TaskRuntime], Awaitable[FinalSemanticEvaluation]
]

_REPOSITORY: str = getattr(non_dispatch, "_REPOSITORY")
_INSTALLATION: str = getattr(non_dispatch, "_INSTALLATION")
_PROVIDER: ProviderBinding = getattr(non_dispatch, "_PROVIDER")
_Privacy = getattr(non_dispatch, "_Privacy")
_Catalog = getattr(non_dispatch, "_Catalog")
_route_for = getattr(non_dispatch, "_route_for")
_durable_semantic_case = getattr(non_dispatch, "_durable_semantic_case")
_PolicyApplication = getattr(non_dispatch, "_PolicyApplication")
_test_effective_policy = getattr(non_dispatch, "_test_effective_policy")
_SECRET = "ghp_" + "Q" * 36
_packet_limits = getattr(check_module, "_packet_limits")


def _git(repository: Path, *arguments: str) -> None:
    subprocess.run(
        (
            "git",
            "-c",
            "user.name=FinishUP Test",
            "-c",
            "user.email=finishup@example.invalid",
            *arguments,
        ),
        cwd=repository,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=True,
        env={
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "HOME": os.fspath(repository),
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": os.defpath,
        },
    )


def _repository(tmp_path: Path) -> Path:
    repository = tmp_path / "kea"
    repository.mkdir(mode=0o700)
    _git(repository, "init", "--quiet")
    (repository / "atomic-selectors.ts").write_text(
        "export function trackKey(key: number | string) {\n"
        "  return dependencies.get(String(key));\n"
        "}\n",
        encoding="utf-8",
    )
    (repository / ".gitignore").write_text("local.env\n", encoding="utf-8")
    _git(repository, "add", "--", "atomic-selectors.ts", ".gitignore")
    _git(repository, "commit", "--quiet", "-m", "baseline")
    return repository


def _python_rewrite(repository: Path, old: str, new: str) -> None:
    """Edit like the kea attempt: ``open(p).read().replace(...)`` in a shell Python call."""

    script = (
        "import sys\n"
        "path, old, new = sys.argv[1:]\n"
        "text = open(path).read()\n"
        "assert old in text\n"
        "open(path, 'w').write(text.replace(old, new))\n"
    )
    subprocess.run(
        (sys.executable, "-c", script, "atomic-selectors.ts", old, new),
        cwd=repository,
        check=True,
        capture_output=True,
    )


def _evaluator(privacy: object, runtime: TaskRuntime) -> _Evaluator:
    async def resolve_provider() -> ProviderBinding | None:
        return _PROVIDER

    factory = cast(
        "Callable[..., _Evaluator]",
        getattr(ready_composition_module, "_privacy_gated_semantic_evaluator"),
    )
    return factory(
        cast(PrivacyCoordinator, privacy),
        FixedClock(),
        _INSTALLATION,
        resolve_provider,
        cast(StartCatalogPort, _Catalog(_route_for(runtime.task_id, runtime.session_id))),
        ready_composition_module.IdPort(),
        change_capture=GitChangeCaptureAdapter(),
    )


def _change_text(candidate: CandidateContext) -> str:
    parts = [
        item.plaintext.decode("utf-8")
        for item in candidate.items
        if item.item_id.startswith(CHECK_TIME_CHANGE_ITEM_PREFIX)
    ]
    assert parts, "the packet carries no check-time change"
    return "".join(parts)


def _packet_gaps(candidate: CandidateContext) -> list[str]:
    """The known gaps the review packet the privacy gateway was offered carries."""

    envelope = strict_json_parse(
        next(item.plaintext for item in candidate.items if item.item_id == REVIEW_PACKET_ITEM_ID)
    )
    assert isinstance(envelope, dict)
    packet = cast(dict[str, object], envelope["review_packet"])
    coverage = cast(dict[str, object], packet["coverage"])
    return cast(list[str], coverage["known_gaps"])


@pytest.fixture(autouse=True)
def isolated_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    monkeypatch.setenv("HOME", os.fspath(home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.setattr(diagnostics_module, "log_dir", lambda: tmp_path / "logs")


def _with_claim(frozen: FrozenCase) -> FrozenCase:
    """The durable lease, over a case holding the claim and obligation the change serves."""

    obligation = obligation_record(
        ObligationPublishedPayload(
            obl(1), "Keep numeric and string keys apart", "tests pass", ObligationStatus.OPEN
        ),
        1,
    )
    claim = record(
        ClaimRecordedPayload(
            clm(1),
            ClaimKind.COMPLETION,
            "Atomic selectors now track numeric and string keys separately",
            (),
            obligation_refs=(obl(1),),
        ),
        1,
    )
    case = make_case(
        obligations={obl(1): obligation}, claims={clm(1): claim}, extra_refs=(clm(1), obl(1))
    )
    frontier = frozen.lease.frontier
    case = replace(
        case,
        projection=replace(
            case.projection, frontier=frontier.sequence, head_digest=frontier.head_digest
        ),
        frontier=frontier,
    )
    return FrozenCase(case, frozen.lease)


async def _kea_case(
    adapter: MemoryLedgerAdapter | SqliteLedger, repository: Path
) -> tuple[FrozenCase, TaskRuntime]:
    frozen, runtime = await _durable_semantic_case(adapter)
    assert await record_task_change_base(
        runtime=runtime,
        port=GitChangeCaptureAdapter(),
        workspace=os.fspath(repository),
        clock=FixedClock(),
    )
    return _with_claim(frozen), runtime


@pytest.mark.anyio
@pytest.mark.parametrize(
    "adapter_factory", (memory_adapter, sqlite_adapter), ids=("memory", "sqlite")
)
async def test_shell_rewrites_and_commits_reach_the_packet_and_survive_replay(
    tmp_path: Path,
    adapter_factory: Callable[[object], MemoryLedgerAdapter | SqliteLedger],
) -> None:
    repository = _repository(tmp_path)
    adapter = adapter_factory(append_command())
    frozen, runtime = await _kea_case(adapter, repository)

    # 34 rewrites in the benchmark; two here, one committed and one left in the working tree.
    _python_rewrite(repository, "String(key)", "`${typeof key}:${String(key)}`")
    _git(repository, "commit", "--quiet", "-am", "keep numeric and string keys apart")
    _python_rewrite(repository, "dependencies.get", "dependencyMap.get")
    (repository / "atomic-selectors.test.ts").write_text(
        f"const fixtureToken = '{_SECRET}';\nexpect(trackKey(1)).not.toBe(trackKey('1'));\n",
        encoding="utf-8",
    )
    (repository / "local.env").write_text("IGNORED_CANARY=1\n", encoding="utf-8")

    privacy = _Privacy(task_id=runtime.task_id, profile=ReviewContextProfile.EXPANDED)
    evaluator = _evaluator(privacy, runtime)
    source = CheckWorkspaceSource(os.fspath(repository), _REPOSITORY)
    with check_workspace_source_scope(source):
        waiting = await evaluator(frozen, (), runtime)

    assert waiting.status is SemanticStatus.AWAITING_HUMAN
    candidate = privacy.candidates[0]
    envelope = strict_json_parse(
        next(item.plaintext for item in candidate.items if item.item_id == REVIEW_PACKET_ITEM_ID)
    )
    assert isinstance(envelope, dict)
    packet = cast(dict[str, object], envelope["review_packet"])
    excerpts = cast(list[dict[str, object]], packet["targeted_excerpts"])
    assert excerpts[0]["excerpt_item_id"] == f"{CHECK_TIME_CHANGE_ITEM_PREFIX}001"
    text = _change_text(candidate)
    assert "Base: the commit HEAD named when this task started." in text
    assert "`${typeof key}:${String(key)}`" in text  # committed rewrite
    assert "dependencyMap.get" in text  # uncommitted rewrite
    assert "expect(trackKey(1)).not.toBe(trackKey('1'));" in text  # untracked file
    assert "IGNORED_CANARY" not in text and "local.env" not in text
    # Capture-time redaction ran with the same detector as the egress never-send scan.
    assert _SECRET not in text and "[REDACTED]" in text
    assert all(scan_exact_bytes(item.plaintext) == () for item in candidate.items)
    assert CHECK_TIME_CHANGE_REDACTED_GAP in waiting.case_content_gaps
    assert CHECK_TIME_CHANGE_BASE_UNAVAILABLE_GAP not in waiting.case_content_gaps
    # The change text itself was redacted: a reviewer's diff request is FinishUP's packet limit.
    assert CHECK_TIME_CHANGE_TRUNCATED_GAP not in waiting.case_content_gaps
    assert _packet_limits(waiting, ())["change_clipped"]
    # Keyed commitments to the files the packet carried: the rewritten file whole, the test file
    # with its redacted fixture token only in part (ADR-031 resolution rule).
    shown = waiting.check_change_files
    assert shown is not None and shown.complete
    assert len(shown.fully_shown) == 1 and len(shown.partially_shown) == 1
    objects = cast(MemoryObjects, getattr(adapter, "_objects"))
    assert len(objects.refs_for_kind(ObjectKind.CHANGE_CAPTURE)) == 2  # base + one change

    # The agent keeps editing while the disclosure waits. The replay must review the frozen
    # capture, not re-read the tree: same case digest, same object, same packet text.
    _python_rewrite(repository, "dependencyMap.get", "dependencyMapAfterWait.get")
    assert waiting.operation_lease is not None
    privacy.resume_terminal = (PrivacyOutcome.HUMAN_DENIED, PrivacyReason.HUMAN_DENIED)
    with check_workspace_source_scope(source):
        resumed = await evaluator(FrozenCase(frozen.case, waiting.operation_lease), (), runtime)

    assert resumed.status is SemanticStatus.HUMAN_DENIED
    assert privacy.resume_calls == 1
    assert resumed.case_content_gaps == waiting.case_content_gaps
    assert resumed.check_change_files == waiting.check_change_files
    assert len(objects.refs_for_kind(ObjectKind.CHANGE_CAPTURE)) == 2


@pytest.mark.anyio
async def test_connection_for_another_repository_is_never_read(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    adapter = memory_adapter(append_command())
    frozen, runtime = await _kea_case(adapter, repository)
    _python_rewrite(repository, "String(key)", "OTHER_REPOSITORY_CANARY")
    privacy = _Privacy(task_id=runtime.task_id, profile=ReviewContextProfile.EXPANDED)

    other = CheckWorkspaceSource(os.fspath(repository), "hmac-sha256:" + "e" * 64)
    with check_workspace_source_scope(other):
        waiting = await _evaluator(privacy, runtime)(frozen, (), runtime)

    assert CHECK_TIME_CHANGE_UNAVAILABLE_GAP in waiting.case_content_gaps
    # The typed reason reaches the check's coverage as a closed code, never as text.
    assert "check_time_change_unavailable_repository_mismatch" in waiting.case_content_gaps
    candidate = privacy.candidates[0]
    assert not any(
        item.item_id.startswith(CHECK_TIME_CHANGE_ITEM_PREFIX) for item in candidate.items
    )
    assert all(b"OTHER_REPOSITORY_CANARY" not in item.plaintext for item in candidate.items)
    objects = cast(MemoryObjects, getattr(adapter, "_objects"))
    assert len(objects.refs_for_kind(ObjectKind.CHANGE_CAPTURE)) == 1  # the base only


@pytest.mark.anyio
async def test_task_without_a_recorded_base_pins_its_first_check_and_discloses_it(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path)
    frozen, runtime = await _durable_semantic_case(memory_adapter(append_command()))
    frozen = _with_claim(frozen)
    _python_rewrite(repository, "String(key)", "HEAD_BASE_MARKER")
    privacy = _Privacy(task_id=runtime.task_id, profile=ReviewContextProfile.EXPANDED)

    with check_workspace_source_scope(CheckWorkspaceSource(os.fspath(repository), _REPOSITORY)):
        waiting = await _evaluator(privacy, runtime)(frozen, (), runtime)

    # Still not the task-start commit, so still disclosed as such.
    assert CHECK_TIME_CHANGE_BASE_UNAVAILABLE_GAP in waiting.case_content_gaps
    text = _change_text(privacy.candidates[0])
    assert "HEAD_BASE_MARKER" in text
    assert "the state at this task's first check (the commit at task start" in text
    assert await getattr(runtime.ledger, "load_task_change_base")() is not None


@pytest.mark.anyio
async def test_legacy_task_keeps_its_pinned_base_across_a_repair_commit(tmp_path: Path) -> None:
    """ADR-031: a task with no start base must not re-base on HEAD at every check."""

    repository = _repository(tmp_path)
    _, runtime = await _durable_semantic_case(memory_adapter(append_command()))
    port = GitChangeCaptureAdapter()
    source = CheckWorkspaceSource(os.fspath(repository), _REPOSITORY)

    async def check(suffix: str) -> tuple[CheckChangeCapture, CheckChangeShownFiles]:
        outcome = await capture_check_time_change(
            runtime=runtime,
            source=source,
            route_repository_commitment=_REPOSITORY,
            port=port,
            clock=FixedClock(),
            request_id=f"req_00000000-0000-4000-8000-0000000007{suffix}",
        )
        assert outcome.change is not None
        capture = outcome.change.capture
        files = await check_change_shown_files(runtime, outcome.change, len(capture.text))
        return capture, files

    _python_rewrite(repository, "String(key)", "`${typeof key}:${String(key)}`")
    raising_capture, raised = await check("01")
    _git(repository, "commit", "--quiet", "-am", "keep numeric and string keys apart")
    _python_rewrite(repository, "dependencies.get", "dependencyMap.get")
    repair_capture, repair = await check("02")

    assert raising_capture.base == repair_capture.base == "first_check"
    assert raising_capture.base_commit == repair_capture.base_commit
    # The committed work is still part of the change, and the file matches across the commit.
    assert b"`${typeof key}:${String(key)}`" in repair_capture.text
    assert raised.fully_shown and repair.covers(raised)


@pytest.mark.anyio
async def test_change_larger_than_the_packet_is_truncated_and_disclosed(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    adapter = memory_adapter(append_command())
    frozen, runtime = await _kea_case(adapter, repository)
    # About 150 KiB of diff: more than the whole packet's excerpt budget can carry.
    for index in range(20):
        (repository / f"module_{index:02d}.ts").write_text(
            "".join(f"export const value{line} = {line};\n" for line in range(240)),
            encoding="utf-8",
        )
    privacy = _Privacy(task_id=runtime.task_id, profile=ReviewContextProfile.EXPANDED)

    with check_workspace_source_scope(CheckWorkspaceSource(os.fspath(repository), _REPOSITORY)):
        waiting = await _evaluator(privacy, runtime)(frozen, (), runtime)

    assert CHECK_TIME_CHANGE_TRUNCATED_GAP in waiting.case_content_gaps
    text = _change_text(privacy.candidates[0])
    # The header names every changed file, including the ones whose hunks did not fit.
    for index in range(20):
        assert f"  A module_{index:02d}.ts (+240 -0) untracked" in text
    assert "[FinishUP check-time change, part 1 of " in text


@pytest.mark.anyio
async def test_no_trusted_workspace_source_leaves_the_case_as_before(tmp_path: Path) -> None:
    del tmp_path
    frozen, runtime = await _durable_semantic_case(memory_adapter(append_command()))
    frozen = _with_claim(frozen)
    privacy = _Privacy(task_id=runtime.task_id, profile=ReviewContextProfile.EXPANDED)

    waiting = await _evaluator(privacy, runtime)(frozen, (), runtime)

    assert not {
        CHECK_TIME_CHANGE_UNAVAILABLE_GAP,
        CHECK_TIME_CHANGE_BASE_UNAVAILABLE_GAP,
    } & set(waiting.case_content_gaps)
    assert not any(
        item.item_id.startswith(CHECK_TIME_CHANGE_ITEM_PREFIX)
        for item in privacy.candidates[0].items
    )


def _inference_policy_without_repository_excerpts() -> EffectivePrivacyPolicy:
    """An expanded recipe whose inference channel allows evidence but not repository excerpts."""

    base = cast(EffectivePrivacyPolicy, _test_effective_policy(ReviewContextProfile.EXPANDED))
    allowed = tuple(
        sorted(
            base.policy.review_selection.required_categories() - {DataCategory.REPOSITORY_EXCERPT},
            key=lambda item: item.value,
        )
    )
    assert DataCategory.EVIDENCE_EXCERPT in allowed
    channels = tuple(
        ChannelPolicy(
            channel.channel,
            True,
            allowed,
            (DataClass.ORDINARY_USER_CONTENT, DataClass.PUBLIC_STRUCTURAL),
            _PROVIDER,
            ("selected-code-review",),
            AuthorizationScopeKind.TASK,
            False,
            262_144,
            65_536,
            3_600,
        )
        if channel.channel is EgressChannel.LLM_INFERENCE
        else channel
        for channel in base.policy.channel_policies
    )
    policy = replace(
        base.policy,
        profile=PrivacyProfile.TRUSTED_PROVIDER,
        network_egress_permitted=True,
        channel_policies=channels,
    )
    return EffectivePrivacyPolicy(policy, base.generation, base.effective_digest)


@pytest.mark.anyio
async def test_channel_denying_repository_excerpts_never_sends_the_change_and_says_so(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path)
    frozen, runtime = await _kea_case(memory_adapter(append_command()), repository)
    _python_rewrite(repository, "String(key)", "`${typeof key}:${String(key)}`")
    effective = _inference_policy_without_repository_excerpts()
    privacy = _Privacy(task_id=runtime.task_id, profile=ReviewContextProfile.EXPANDED)
    privacy.policy_application = _PolicyApplication(effective, repository_granted=True)

    source = CheckWorkspaceSource(os.fspath(repository), _REPOSITORY)
    with check_workspace_source_scope(source):
        waiting = await _evaluator(privacy, runtime)(frozen, (), runtime)

    # Disclosed: the recipe selects the change, the channel withholds its category.
    assert effective.policy.withheld_review_categories == (DataCategory.REPOSITORY_EXCERPT,)
    assert waiting.withheld_review_categories == ("repository_excerpt",)
    # R945-06: a review whose channel withholds the change is never recorded as having seen it.
    assert waiting.check_change_files == CheckChangeShownFiles((), (), complete=True)
    candidate = privacy.candidates[0]
    change_items = [
        item for item in candidate.items if item.item_id.startswith(CHECK_TIME_CHANGE_ITEM_PREFIX)
    ]
    assert change_items
    assert all(item.category is DataCategory.REPOSITORY_EXCERPT for item in change_items)
    # Never sent: the real enforcer and gateway decision approve everything else, not the change.
    classified = LocalPrivacyEnforcer().classify(candidate, effective)
    coordinator = object.__new__(PrivacyCoordinator)
    decision = coordinator._semantic_decision(  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
        classified, effective, _PROVIDER
    )
    assert decision.outcome is PrivacyOutcome.COMPLETED
    assert REVIEW_PACKET_ITEM_ID in decision.approved_item_ids
    assert not any(
        item_id.startswith(CHECK_TIME_CHANGE_ITEM_PREFIX) for item_id in decision.approved_item_ids
    )
    assert DataCategory.REPOSITORY_EXCERPT in decision.blocked_categories


@pytest.mark.anyio
async def test_shown_file_commitments_are_keyed_to_the_task_and_bound_to_the_base() -> None:
    _, runtime = await _durable_semantic_case(memory_adapter(append_command()))
    text = b"Header\nEnd of header.\ndiff --git a/atomic-selectors.ts b/atomic-selectors.ts\n+x\n"
    stored = ObjectRef(
        object_id="obj_00000000-0000-4000-8000-000000000901",
        plaintext_size=len(text) + 100,
        commitment="hmac-sha256:" + "9" * 64,
        envelope_digest="sha256:" + "a" * 64,
        encryption_format="yoetz-object/1",
        key_slot="task",
        metadata=ObjectMetadata(
            ObjectKind.CHANGE_CAPTURE,
            CHECK_CHANGE_MEDIA_TYPE,
            runtime.task_id,
            datetime(2026, 9, 29, tzinfo=UTC),
        ),
    )

    async def commitments(base_commit: str) -> tuple[str, ...]:
        capture = CheckChangeCapture(
            base="head",
            text=text,
            tracked_files=1,
            untracked_files=0,
            omitted_files=0,
            truncated=False,
            base_commit=base_commit,
        )
        files = await check_change_shown_files(runtime, CheckTimeChange(stored, capture), len(text))
        assert files.complete and not files.partially_shown
        return files.fully_shown

    first = await commitments("1" * 40)
    assert first == await commitments("1" * 40)  # the same file under the same base
    assert first != await commitments("2" * 40)  # HEAD moved: a different file identity
    assert len(first) == 1 and first[0].startswith("hmac-sha256:")
    assert "atomic" not in first[0]


@pytest.mark.anyio
async def test_shown_files_that_cannot_be_committed_are_recorded_incomplete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = _repository(tmp_path)
    frozen, runtime = await _kea_case(memory_adapter(append_command()), repository)
    _python_rewrite(repository, "String(key)", "`${typeof key}:${String(key)}`")

    async def failing(*args: object, **kwargs: object) -> object:
        del args, kwargs
        raise RuntimeError("commitment key unavailable")

    monkeypatch.setattr(ready_composition_module, "check_change_shown_files", failing)
    privacy = _Privacy(task_id=runtime.task_id, profile=ReviewContextProfile.EXPANDED)
    with check_workspace_source_scope(CheckWorkspaceSource(os.fspath(repository), _REPOSITORY)):
        waiting = await _evaluator(privacy, runtime)(frozen, (), runtime)

    # The review still proceeds; the record just never tolerates a check-time limit.
    assert waiting.status is SemanticStatus.AWAITING_HUMAN
    assert waiting.check_change_files == CheckChangeShownFiles((), (), complete=False)


async def _files_for(runtime: TaskRuntime, repository: Path, suffix: str) -> CheckChangeShownFiles:
    outcome = await capture_check_time_change(
        runtime=runtime,
        source=CheckWorkspaceSource(os.fspath(repository), _REPOSITORY),
        route_repository_commitment=_REPOSITORY,
        port=GitChangeCaptureAdapter(),
        clock=FixedClock(),
        request_id=f"req_00000000-0000-4000-8000-0000000008{suffix}",
    )
    assert outcome.change is not None
    return await check_change_shown_files(
        runtime,
        outcome.change,
        len(outcome.change.capture.text),
    )


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("before", "after", "covered"),
    [
        ("text", "binary", False),
        ("binary", "binary", True),
        ("text", "deleted", False),
        ("text", "text", True),
    ],
)
async def test_a_file_whose_change_kind_changed_never_matches_itself(
    tmp_path: Path, before: str, after: str, covered: bool
) -> None:
    """A binary or deleted file shows no code; it must not stand in for a shown text diff."""

    repository = _repository(tmp_path)
    _, runtime = await _durable_semantic_case(memory_adapter(append_command()))
    target = repository / "atomic-selectors.ts"

    def change(kind: str, marker: bytes) -> None:
        if kind == "deleted":
            target.unlink()
        elif kind == "binary":
            target.write_bytes(b"\0binary " + marker)
        else:
            target.write_bytes(target.read_bytes() + b"export const marker = '" + marker + b"';\n")

    change(before, b"one")
    raised = await _files_for(runtime, repository, "01")
    if after != "deleted":
        change(after, b"two")
    else:
        change(after, b"")
    repair = await _files_for(runtime, repository, "02")

    assert raised.fully_shown  # the file was shown whole to the raising review
    assert repair.covers(raised) is covered


@pytest.mark.anyio
async def test_nested_repository_task_input_and_deliverables_reach_the_recorded_packet(
    tmp_path: Path,
) -> None:
    """Issue #1045: live-database-cutover's nested ``api`` repository, vba-userform-port's input
    file and the declared deliverables all reach the packet the privacy gateway is offered."""

    from builders.policy_cases import evt, plan_record
    from finishup.domain.events import (
        PlanPublishedPayload,
        RequestedItem,
        RequestedItemKind,
        RequestedItemRole,
    )
    from finishup.domain.task_statement import RecordedTaskStatement

    repository = _repository(tmp_path)
    (repository / "spec").mkdir()
    (repository / "spec" / "RULES.md").write_text(
        "# Cutover rules\nRULES_INPUT_MARKER: never drop the legacy table first.\n",
        encoding="utf-8",
    )
    _git(repository, "add", "--", "spec/RULES.md")
    _git(repository, "commit", "--quiet", "-m", "rules")
    (repository / "index.json").write_text('{"PREEXISTING_MARKER": 1}\n', encoding="utf-8")
    nested = repository / "api"
    nested.mkdir(mode=0o700)
    _git(nested, "init", "--quiet")
    (nested / "server.py").write_text("DATABASE = 'legacy'\n", encoding="utf-8")
    _git(nested, "add", "--", "server.py")
    _git(nested, "commit", "--quiet", "-m", "api baseline")

    adapter = memory_adapter(append_command())
    frozen, runtime = await _kea_case(adapter, repository)
    (nested / "server.py").write_text("DATABASE = 'NESTED_CUTOVER_MARKER'\n", encoding="utf-8")

    obligation = obligation_record(
        ObligationPublishedPayload(
            obl(1),
            "Cut the API over",
            "api/server.py uses the new database",
            ObligationStatus.OPEN,
            requested_items=(
                RequestedItem(RequestedItemKind.FILE, "api/server.py", RequestedItemRole.OUTPUT),
            ),
        ),
        1,
    )
    claim = record(
        ClaimRecordedPayload(
            clm(1), ClaimKind.COMPLETION, "Cut over", (), obligation_refs=(obl(1),)
        ),
        1,
    )
    case = make_case(
        plans={1: plan_record(PlanPublishedPayload(1, "Cut over", (obl(1),)), 1)},
        obligations={obl(1): obligation},
        claims={clm(1): claim},
        extra_refs=(clm(1), obl(1), evt(1)),
    )
    lease_frontier = frozen.lease.frontier
    case = replace(
        case,
        projection=replace(
            case.projection,
            frontier=lease_frontier.sequence,
            head_digest=lease_frontier.head_digest,
        ),
        frontier=lease_frontier,
        task_statement=RecordedTaskStatement(
            text="Cut the API over to the new database; follow spec/RULES.md exactly.",
            source_event_id=evt(1),
            source_family="session_opened",
            ingestion_sequence=1,
        ),
    )
    frozen = FrozenCase(case, frozen.lease)

    privacy = _Privacy(task_id=runtime.task_id, profile=ReviewContextProfile.EXPANDED)
    with check_workspace_source_scope(CheckWorkspaceSource(os.fspath(repository), _REPOSITORY)):
        waiting = await _evaluator(privacy, runtime)(frozen, (), runtime)

    assert waiting.status is SemanticStatus.AWAITING_HUMAN
    candidate = privacy.candidates[0]
    change = _change_text(candidate)
    # The nested repository's own diff, under its directory, from its task-start commit.
    assert "Nested repository api/: its own change is shown under that directory" in change
    assert "+DATABASE = 'NESTED_CUTOVER_MARKER'" in change
    # The untracked file that predates the task is baseline, not an addition.
    assert "PREEXISTING_MARKER" not in change and "index.json" not in change
    items = {item.item_id: item for item in candidate.items}
    task_input = items["task-input-01"]
    assert task_input.category is DataCategory.REPOSITORY_EXCERPT
    assert b"RULES_INPUT_MARKER" in task_input.plaintext
    deliverables = items["declared-deliverables"]
    assert deliverables.category is DataCategory.OBLIGATION_TEXT
    body = strict_json_parse(deliverables.plaintext)
    assert isinstance(body, dict)
    rows = cast(list[dict[str, object]], body["deliverables"])
    assert [row["in_check_time_change"] for row in rows] == ["modified"]
    # Recorded and egress-counted like every other item: the composed manifest lists the input.
    envelope = strict_json_parse(items[REVIEW_PACKET_ITEM_ID].plaintext)
    assert isinstance(envelope, dict)
    packet = cast(dict[str, object], envelope["review_packet"])
    manifest = cast(dict[str, object], packet["review_input_manifest"])
    caller = cast(dict[str, object], manifest["caller_evidence"])
    assert "task-input-01" in cast(list[str], caller["item_ids"])
    assert "declared-deliverables" in cast(list[str], packet["obligation_item_ids"])
    assert all(scan_exact_bytes(item.plaintext) == () for item in candidate.items)


@pytest.mark.anyio
async def test_changed_submodule_whose_own_change_is_not_read_is_disclosed_as_truncated(
    tmp_path: Path,
) -> None:
    """Review of #1045: a submodule checkout is never opened, so the check's coverage must say
    its change was cut even though the gitlink's commit-id lines are shown."""

    repository = _repository(tmp_path)
    nested = repository / "api"
    nested.mkdir(mode=0o700)
    _git(nested, "init", "--quiet", f"--separate-git-dir={tmp_path / 'api.git'}")
    (nested / "server.py").write_text("DATABASE = 'legacy'\n", encoding="utf-8")
    _git(nested, "add", "--", "server.py")
    _git(nested, "commit", "--quiet", "-m", "api baseline")
    _git(repository, "add", "--", "api")
    _git(repository, "commit", "--quiet", "-m", "track api")
    frozen, runtime = await _kea_case(memory_adapter(append_command()), repository)
    (nested / "server.py").write_text("DATABASE = 'SUBMODULE_CANARY'\n", encoding="utf-8")
    _git(nested, "commit", "--quiet", "-am", "cut over")
    privacy = _Privacy(task_id=runtime.task_id, profile=ReviewContextProfile.EXPANDED)

    with check_workspace_source_scope(CheckWorkspaceSource(os.fspath(repository), _REPOSITORY)):
        waiting = await _evaluator(privacy, runtime)(frozen, (), runtime)

    text = _change_text(privacy.candidates[0])
    assert "SUBMODULE_CANARY" not in text
    assert "Nested repository api/: its own change is not shown" in text
    assert "Not shown: 1." in text
    assert CHECK_TIME_CHANGE_TRUNCATED_GAP in _packet_gaps(privacy.candidates[0])
    assert CHECK_TIME_CHANGE_TRUNCATED_GAP in waiting.case_content_gaps


@pytest.mark.anyio
async def test_a_nested_repository_never_sends_what_predates_the_task_as_its_change(
    tmp_path: Path,
) -> None:
    """Review of #1045: a gitlinked repository's commit made before the task (never recorded by
    the outer gitlink) and a developer's untracked note inside it reached the packet as the
    agent's change. The recorded task-start base now carries the repository's own HEAD and its
    untracked listing: the note is its starting state, while the agent's new file is shown."""

    repository = _repository(tmp_path)
    nested = repository / "api"
    nested.mkdir(mode=0o700)
    _git(nested, "init", "--quiet")
    (nested / "server.py").write_text("DATABASE = 'legacy'\n", encoding="utf-8")
    _git(nested, "add", "--", "server.py")
    _git(nested, "commit", "--quiet", "-m", "api baseline")
    _git(repository, "add", "--", "api")
    _git(repository, "commit", "--quiet", "-m", "track api")
    (nested / "private.py").write_text("PRE_TASK_COMMIT_MARKER = 1\n", encoding="utf-8")
    _git(nested, "add", "--", "private.py")
    _git(nested, "commit", "--quiet", "-m", "committed inside api only, before the task")
    (nested / "notes.md").write_text("NESTED_NOTE_MARKER\n", encoding="utf-8")
    frozen, runtime = await _kea_case(memory_adapter(append_command()), repository)
    (nested / "server.py").write_text("DATABASE = 'NESTED_CUTOVER_MARKER'\n", encoding="utf-8")
    (nested / "migrate.py").write_text("NESTED_MIGRATION_MARKER = 1\n", encoding="utf-8")
    privacy = _Privacy(task_id=runtime.task_id, profile=ReviewContextProfile.EXPANDED)

    with check_workspace_source_scope(CheckWorkspaceSource(os.fspath(repository), _REPOSITORY)):
        waiting = await _evaluator(privacy, runtime)(frozen, (), runtime)

    candidate = privacy.candidates[0]
    text = _change_text(candidate)
    assert "+DATABASE = 'NESTED_CUTOVER_MARKER'" in text
    assert "+NESTED_MIGRATION_MARKER = 1" in text  # the agent's new file inside the repository
    assert "PRE_TASK_COMMIT_MARKER" not in text and "api/private.py" not in text
    assert "NESTED_NOTE_MARKER" not in text and "api/notes.md" not in text
    assert "from the commit it held when the task started.\n" in text
    assert all(b"NESTED_NOTE_MARKER" not in item.plaintext for item in candidate.items)
    assert all(b"PRE_TASK_COMMIT_MARKER" not in item.plaintext for item in candidate.items)
    assert CHECK_TIME_CHANGE_TRUNCATED_GAP not in _packet_gaps(candidate)
    assert CHECK_TIME_CHANGE_TRUNCATED_GAP not in waiting.case_content_gaps


@pytest.mark.anyio
async def test_a_redacted_task_input_is_disclosed_even_when_the_change_is_clean(
    tmp_path: Path,
) -> None:
    """Review of #1045: redacting only a task input file still reports the redaction."""

    from builders.policy_cases import evt
    from finishup.domain.task_statement import RecordedTaskStatement

    repository = _repository(tmp_path)
    (repository / "spec").mkdir()
    (repository / "spec" / "RULES.md").write_text(
        f"# Rules\nRULES_INPUT_MARKER\ndeploy_token = '{_SECRET}'\n", encoding="utf-8"
    )
    _git(repository, "add", "--", "spec/RULES.md")
    _git(repository, "commit", "--quiet", "-m", "rules")
    frozen, runtime = await _kea_case(memory_adapter(append_command()), repository)
    _python_rewrite(repository, "String(key)", "`${typeof key}:${String(key)}`")
    frozen = FrozenCase(
        replace(
            frozen.case,
            task_statement=RecordedTaskStatement(
                text="Keep numeric and string keys apart; follow spec/RULES.md exactly.",
                source_event_id=evt(1),
                source_family="session_opened",
                ingestion_sequence=1,
            ),
        ),
        frozen.lease,
    )
    privacy = _Privacy(task_id=runtime.task_id, profile=ReviewContextProfile.EXPANDED)

    with check_workspace_source_scope(CheckWorkspaceSource(os.fspath(repository), _REPOSITORY)):
        waiting = await _evaluator(privacy, runtime)(frozen, (), runtime)

    candidate = privacy.candidates[0]
    assert "[REDACTED]" not in _change_text(candidate)  # the change itself needed nothing
    task_input = next(item for item in candidate.items if item.item_id == "task-input-01")
    assert b"RULES_INPUT_MARKER" in task_input.plaintext
    assert _SECRET.encode() not in task_input.plaintext and b"[REDACTED]" in task_input.plaintext
    assert CHECK_TIME_CHANGE_REDACTED_GAP in _packet_gaps(candidate)
    assert CHECK_TIME_CHANGE_REDACTED_GAP in waiting.case_content_gaps
    # Only the input was redacted; the change the packet carried is whole, so a reviewer's diff
    # request stays the agent's to answer.
    assert CHECK_TIME_CHANGE_TRUNCATED_GAP not in waiting.case_content_gaps
    assert not _packet_limits(waiting, ())["change_clipped"]
