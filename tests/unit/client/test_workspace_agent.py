"""The client workspace agent answers each catalog operation exactly as the local adapter would.

Every operation runs against a real temporary Git repository and is compared, after the catalog
round trip, with the same adapter called directly the way a local service calls it. The agent's
own confinements are exercised beside that: only its claimed workspace, outside reads only
beneath admitted roots and never into the workspace or FinishUP's own directories, approved
checks only from the repository's own policy, and closed reasons for everything else.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from finishup.adapters.approved_checks import ApprovedCheckCommand, ApprovedCheckRunner
from finishup.adapters.git_change_capture import GitChangeCaptureAdapter
from finishup.adapters.git_subject_state import (
    GitSubjectStateAdapter,
    list_changed_relative_paths,
    open_local_workspace,
)
from finishup.adapters.task_input_read import (
    list_beneath,
    read_declared_test,
    read_outside_inputs,
    read_text_beneath,
    snapshot_outside_inputs,
)
from finishup.adapters.workspace_inspect import LocalWorkspaceInspectAdapter
from finishup.client import workspace_agent as agent_module
from finishup.client.workspace_agent import (
    WorkspaceAgentHandler,
    client_protected_directories,
    workspace_reply,
)
from finishup.domain.values import JsonObject
from finishup.ports.approved_checks import (
    ApprovedCheckApproval,
    ApprovedCheckStatus,
    approval_commitment,
)
from finishup.ports.change_capture import TaskChangeBase
from finishup.ports.check_sandbox import CheckSandboxLaunch, CheckSandboxStatus
from finishup.ports.control import WorkspaceCall, WorkspaceLocator, WorkspaceReply
from finishup.ports.subject_state import SubjectStateCaptureCommand, SubjectStateFormat
from finishup.ports.workspace_agent import (
    WORKSPACE_OPERATION_NAMES,
    ApprovedCheckRun,
    CaptureArguments,
    CaptureMetadataArguments,
    CheckPolicyRead,
    ClassifyUndeclaredReferencesArguments,
    CountChangeLinesArguments,
    InspectArguments,
    ListBeneathArguments,
    ListChangedPathsArguments,
    LstatCandidatesArguments,
    LstatFacts,
    OpenWorkspaceArguments,
    ProbeRequestedPathsArguments,
    ReadDeclaredTestArguments,
    ReadOutsideInputsArguments,
    ReadTextBeneathArguments,
    RunApprovedCheckArguments,
    SnapshotOutsideInputsArguments,
    SubjectStateCaptureArguments,
    WorkspaceOnlyArguments,
    WorkspaceOperation,
    operation_spec,
    remote_workspace_handle_valid,
)
from finishup.ports.workspace_inspect import WorkspaceInspectCommand
from finishup.protocol.ids import IdKind, new_id

_HANDLE = "client:0123456789abcdef"
_OTHER = "client:fedcba9876543210"
_SERVICE = "svc_00000000-0000-4000-8000-000000000001"
_GIT_ENV = {
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
    "LANG": "C",
    "LC_ALL": "C",
    "PATH": os.defpath,
}
_ECHO = shutil.which("echo", path=os.defpath) or "/bin/echo"
_POLICY = (
    'format = "yoetz.approved-check-policy/1"\n\n'
    "[[checks]]\n"
    'id = "echo"\n'
    f'argv = ["{_ECHO}", "hello"]\n'
    "timeout_seconds = 10\n"
    "network = false\n"
)


@pytest.fixture(autouse=True)
def isolated_global_git(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    monkeypatch.setenv("HOME", os.fspath(home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)


def _git(repository: Path, *arguments: str) -> None:
    subprocess.run(
        ("git", "-c", "user.name=FinishUP Test", "-c", "user.email=t@finishup.invalid", *arguments),
        cwd=repository,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=True,
        env={**_GIT_ENV, "HOME": os.fspath(repository)},
    )


@pytest.fixture
def repository(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    root.mkdir(mode=0o700)
    _git(root, "init", "--quiet")
    (root / "tracked.txt").write_text("one\ntwo\nthree\n", encoding="utf-8")
    (root / "src").mkdir()
    (root / "src" / "app.py").write_text("print('hello')\n", encoding="utf-8")
    (root / "tests").mkdir()
    (root / "tests" / "test_app.py").write_text("def test_app():\n    pass\n", encoding="utf-8")
    (root / ".gitignore").write_text("ignored.log\n", encoding="utf-8")
    _git(root, "add", "-A")
    _git(root, "commit", "--quiet", "-m", "initial")
    return root.resolve()


@pytest.fixture
def shared(tmp_path: Path) -> Path:
    root = (tmp_path / "shared").resolve()
    (root / "data").mkdir(parents=True)
    (root / "spec.md").write_text("SPEC_MARKER\n", encoding="utf-8")
    (root / "data" / "rows.csv").write_text("a,b\n1,2\n", encoding="utf-8")
    return root


@pytest.fixture
def protected(tmp_path: Path) -> Path:
    directory = (tmp_path / "finishup-state").resolve()
    directory.mkdir(mode=0o700)
    (directory / "vault.txt").write_text("VAULT_MARKER\n", encoding="utf-8")
    return directory


def _handler(
    repository: Path, protected: Path, *, operations: Sequence[str] | None = None
) -> WorkspaceAgentHandler:
    return WorkspaceAgentHandler(
        WorkspaceLocator(os.fspath(repository)),
        protected=(os.fspath(protected),),
        operations=operations,
        check_sandbox=_ReadySandbox(),
    )


class _ReadySandbox:
    """The unit seam the approved-check adapter tests use; enforcement has its own tests."""

    def prepare(
        self,
        *,
        argv: Sequence[str],
        cwd: Path,
        env: Mapping[str, str],
        deny_network: bool,
    ) -> CheckSandboxLaunch:
        return CheckSandboxLaunch(
            argv=tuple(argv),
            env=dict(env),
            cwd=cwd,
            status=CheckSandboxStatus.READY,
            network_isolated=deny_network,
        )


def _call(
    operation: WorkspaceOperation, arguments: object, *, deadline_ms: int = 60_000
) -> WorkspaceCall:
    spec = operation_spec(operation)
    assert spec is not None
    return WorkspaceCall(
        kind="workspace_call",
        protocol_version="1.0",
        call_id=new_id(IdKind.CONTROL_RPC),
        service_instance_id=_SERVICE,
        service_generation="1",
        operation=operation.value,
        arguments=JsonObject(spec.encode_arguments(arguments)),
        deadline_ms=deadline_ms,
    )


def _reply(
    handler: WorkspaceAgentHandler,
    operation: WorkspaceOperation,
    arguments: object,
    *,
    handle: str | None = _HANDLE,
) -> WorkspaceReply:
    call = _call(operation, arguments)
    reply = handler.answer(call, workspace_handle=handle)
    assert reply.call_id == call.call_id
    return reply


def _ok(
    handler: WorkspaceAgentHandler,
    operation: WorkspaceOperation,
    arguments: object,
    *,
    handle: str | None = _HANDLE,
) -> Any:
    reply = _reply(handler, operation, arguments, handle=handle)
    assert (reply.outcome, reply.reason) == ("ok", None)
    spec = operation_spec(operation)
    assert spec is not None
    return spec.decode_result(reply.result)


def _refused(
    handler: WorkspaceAgentHandler,
    operation: WorkspaceOperation,
    arguments: object,
    *,
    handle: str | None = _HANDLE,
) -> tuple[str, str | None]:
    reply = _reply(handler, operation, arguments, handle=handle)
    assert reply.result is None
    return reply.outcome, reply.reason


def _never() -> bool:
    return False


def _change(repository: Path) -> None:
    (repository / "tracked.txt").write_text("one\nTWO\nthree\nfour\n", encoding="utf-8")
    (repository / "new.py").write_text("import json\nprint(json.dumps({}))\n", encoding="utf-8")
    (repository / "ignored.log").write_text("noise\n", encoding="utf-8")
    (repository / "data").mkdir()
    (repository / "data" / "model.bin").write_bytes(b"\x00\x01model")
    (repository / "src" / "app.py").write_text(
        "MODEL = open('data/model.bin', 'rb').read()\nprint('hello')\n", encoding="utf-8"
    )


# --- the declaration -------------------------------------------------------------------------


def test_the_declaration_offers_the_catalog_and_the_frame_bound(
    repository: Path, protected: Path
) -> None:
    handler = _handler(repository, protected)
    assert handler.declaration.operations == WORKSPACE_OPERATION_NAMES
    assert handler.declaration.max_reply_bytes == 6_291_456
    narrowed = _handler(repository, protected, operations=("read_task_base", "capture"))
    assert narrowed.declaration.operations == ("capture", "read_task_base")


def test_a_handler_needs_a_normalized_locator_and_absolute_protected_directories(
    repository: Path,
) -> None:
    with pytest.raises(TypeError, match="workspace_locator_invalid"):
        WorkspaceAgentHandler(os.fspath(repository))  # pyright: ignore[reportArgumentType]
    with pytest.raises(ValueError, match="workspace_locator_path_invalid"):
        WorkspaceAgentHandler(WorkspaceLocator(os.fspath(repository) + "/src/.."))
    with pytest.raises(ValueError, match="workspace_agent_protected_invalid"):
        WorkspaceAgentHandler(WorkspaceLocator(os.fspath(repository)), protected=("relative",))
    with pytest.raises(ValueError, match="workspace_agent_operations_invalid"):
        WorkspaceAgentHandler(WorkspaceLocator(os.fspath(repository)), operations=("rm",))


def test_the_default_protected_directories_are_this_clients_own(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = tmp_path / "isolated"
    monkeypatch.setattr(agent_module.config_paths, "isolated_root", lambda: root)
    monkeypatch.setattr(agent_module.config_paths, "bundle_root", lambda: root / "data")
    monkeypatch.setattr(
        agent_module.config_paths, "config_file_path", lambda: root / "config" / "config.toml"
    )
    monkeypatch.setattr(agent_module.config_paths, "cache_dir", lambda: root / "cache")
    monkeypatch.setattr(agent_module.config_paths, "state_dir", lambda: root / "state")

    def unresolvable() -> Path:
        raise RuntimeError("isolation_root_invalid")

    monkeypatch.setattr(agent_module.config_paths, "log_dir", unresolvable)
    monkeypatch.setattr(agent_module.config_paths, "runtime_dir", lambda: root / "run")
    ambient = tmp_path / "ambient"
    monkeypatch.setattr(
        agent_module.config_paths,
        "ambient_installation_dirs",
        lambda: (ambient / "finishup", root / "state", ambient / "yoetz"),
    )
    assert client_protected_directories() == tuple(
        os.fspath(path)
        for path in (
            root,
            root / "data",
            root / "config",
            root / "cache",
            root / "state",
            root / "run",
            ambient / "finishup",
            ambient / "yoetz",
        )
    )


# --- git -------------------------------------------------------------------------------------


def test_git_operations_equal_the_local_adapter(repository: Path, protected: Path) -> None:
    handler = _handler(repository, protected)
    adapter = GitChangeCaptureAdapter(admitted_home_project=True)
    workspace = os.fspath(repository)

    base = _ok(handler, WorkspaceOperation.READ_TASK_BASE, WorkspaceOnlyArguments(_HANDLE))
    assert type(base) is TaskChangeBase
    assert base == adapter.read_task_base(workspace)

    _change(repository)
    capture = _ok(
        handler,
        WorkspaceOperation.CAPTURE,
        CaptureArguments(
            _HANDLE,
            base,
            priority_paths=("src/app.py",),
            input_paths=("tracked.txt", "tests/test_app.py"),
        ),
    )
    assert capture == adapter.capture(
        workspace,
        base,
        priority_paths=("src/app.py",),
        input_paths=("tracked.txt", "tests/test_app.py"),
    )
    assert b"TWO" in capture.text

    metadata = _ok(
        handler, WorkspaceOperation.CAPTURE_METADATA, CaptureMetadataArguments(_HANDLE, base)
    )
    assert metadata == adapter.capture_metadata(workspace, base)
    assert {entry.path for entry in metadata.entries} >= {"tracked.txt", "new.py"}

    values = ("tracked.txt", "ignored.log", "new.py", "missing.txt", "/elsewhere/file.txt")
    probes = _ok(
        handler,
        WorkspaceOperation.PROBE_REQUESTED_PATHS,
        ProbeRequestedPathsArguments(_HANDLE, values),
    )
    assert probes == adapter.probe_requested_paths(workspace, values)
    assert [probe.ignored for probe in probes][:2] == [False, True]

    counts = _ok(
        handler,
        WorkspaceOperation.COUNT_CHANGE_LINES,
        CountChangeLinesArguments(_HANDLE, base.commit, ("tracked.txt",)),
    )
    assert counts == adapter.count_change_lines(workspace, base.commit, ("tracked.txt",))
    assert counts.base_lines == (3,)

    references = _ok(
        handler,
        WorkspaceOperation.CLASSIFY_UNDECLARED_REFERENCES,
        ClassifyUndeclaredReferencesArguments(_HANDLE, ("src/app.py",), ("data/model.bin",)),
    )
    assert references == adapter.classify_undeclared_references(
        workspace, ("src/app.py",), ("data/model.bin",)
    )
    assert references == ((0, 0, "dependency"),)


def test_capture_keeps_its_closed_unavailable_reasons(tmp_path: Path, protected: Path) -> None:
    plain = (tmp_path / "plain").resolve()
    plain.mkdir()
    handler = _handler(plain, protected)
    assert _refused(
        handler, WorkspaceOperation.READ_TASK_BASE, WorkspaceOnlyArguments(_HANDLE)
    ) == ("unavailable", "not_git")


@pytest.mark.parametrize("handle", [_OTHER, None])
def test_only_the_claimed_workspace_is_answered(
    repository: Path, protected: Path, handle: str | None
) -> None:
    handler = _handler(repository, protected)
    for operation, arguments in (
        (WorkspaceOperation.READ_TASK_BASE, WorkspaceOnlyArguments(_HANDLE)),
        (WorkspaceOperation.CAPTURE_METADATA, CaptureMetadataArguments(_HANDLE, None)),
        (WorkspaceOperation.LOAD_CHECK_POLICY, WorkspaceOnlyArguments(_HANDLE)),
        (WorkspaceOperation.OPEN_WORKSPACE, OpenWorkspaceArguments(_HANDLE)),
        (
            WorkspaceOperation.READ_TEXT_BENEATH,
            ReadTextBeneathArguments(_HANDLE, "src/app.py"),
        ),
        (
            WorkspaceOperation.READ_DECLARED_TEST,
            ReadDeclaredTestArguments(_HANDLE + "/tests/test_app.py"),
        ),
    ):
        assert _refused(handler, operation, arguments, handle=handle) == (
            "refused",
            "workspace_not_claimed",
        )


# --- reads -----------------------------------------------------------------------------------


def test_outside_inputs_equal_the_local_reader_with_the_local_exclusions(
    repository: Path, protected: Path, shared: Path
) -> None:
    handler = _handler(repository, protected)
    roots = (os.fspath(shared),)
    values = (f"{shared}/spec.md", f"{shared}/data/", f"{shared}/missing.md")
    excluded = (os.fspath(repository), os.fspath(protected))

    inputs = _ok(
        handler,
        WorkspaceOperation.READ_OUTSIDE_INPUTS,
        ReadOutsideInputsArguments(roots, values, limit=4, excluded=(_HANDLE,)),
    )
    assert inputs == read_outside_inputs(roots, values, limit=4, excluded=excluded)
    assert [item.path for item in inputs] == [f"{shared}/spec.md", f"{shared}/data/rows.csv"]

    snapshot = _ok(
        handler,
        WorkspaceOperation.SNAPSHOT_OUTSIDE_INPUTS,
        SnapshotOutsideInputsArguments(
            roots, values, limit=4, max_bytes=65_536, budget_ms=10_000, excluded=(_HANDLE,)
        ),
    )
    assert snapshot == snapshot_outside_inputs(
        roots, values, limit=4, max_bytes=65_536, seconds=10.0, excluded=excluded
    )
    assert snapshot[0].text == b"SPEC_MARKER\n"


def test_outside_reads_never_enter_the_workspace_or_finishup_directories(
    repository: Path, protected: Path, tmp_path: Path
) -> None:
    # The owner admitted a root that holds the workspace and FinishUP's own state; the server
    # names no exclusion at all. The agent still reads neither.
    handler = _handler(repository, protected)
    root = os.fspath(tmp_path.resolve())
    values = (f"{repository}/tracked.txt", f"{protected}/vault.txt")
    assert read_outside_inputs((root,), values, limit=4) != ()  # the bare reader would read them
    assert (
        _ok(
            handler,
            WorkspaceOperation.READ_OUTSIDE_INPUTS,
            ReadOutsideInputsArguments((root,), values, limit=4),
        )
        == ()
    )
    assert (
        _ok(
            handler,
            WorkspaceOperation.SNAPSHOT_OUTSIDE_INPUTS,
            SnapshotOutsideInputsArguments(
                (root,), values, limit=4, max_bytes=65_536, budget_ms=5_000
            ),
        )
        == ()
    )
    # A reviewer read beneath that admitted root is refused the same way.
    assert (
        _ok(
            handler,
            WorkspaceOperation.READ_TEXT_BENEATH,
            ReadTextBeneathArguments(root, "project/tracked.txt"),
        )
        is None
    )
    assert (
        _ok(
            handler,
            WorkspaceOperation.READ_TEXT_BENEATH,
            ReadTextBeneathArguments(root, "finishup-state/vault.txt"),
        )
        is None
    )


@pytest.mark.parametrize("root", ["/etc", "/proc/self", "/srv/.hidden"])
def test_a_root_the_owner_could_never_admit_is_refused(
    repository: Path, protected: Path, root: str
) -> None:
    handler = _handler(repository, protected)
    for operation, arguments in (
        (
            WorkspaceOperation.READ_OUTSIDE_INPUTS,
            ReadOutsideInputsArguments((root,), (f"{root}/passwd",)),
        ),
        (
            WorkspaceOperation.SNAPSHOT_OUTSIDE_INPUTS,
            SnapshotOutsideInputsArguments(
                (root,), (f"{root}/passwd",), limit=1, max_bytes=10, budget_ms=10
            ),
        ),
        (WorkspaceOperation.READ_TEXT_BENEATH, ReadTextBeneathArguments(root, "passwd")),
        (WorkspaceOperation.LIST_BENEATH, ListBeneathArguments(root, "")),
    ):
        assert _refused(handler, operation, arguments) == ("refused", "root_not_admitted")


def test_finishup_directories_are_never_a_read_root(repository: Path, protected: Path) -> None:
    handler = _handler(repository, protected)
    assert _refused(
        handler,
        WorkspaceOperation.LIST_BENEATH,
        ListBeneathArguments(os.fspath(protected), ""),
    ) == ("refused", "root_not_admitted")


def test_reviewer_reads_of_the_workspace_equal_the_local_reader(
    repository: Path, protected: Path
) -> None:
    handler = _handler(repository, protected)
    workspace = os.fspath(repository)
    excluded = (os.fspath(protected),)

    text = _ok(
        handler,
        WorkspaceOperation.READ_TEXT_BENEATH,
        ReadTextBeneathArguments(_HANDLE, "src/app.py", excluded=(os.fspath(protected),)),
    )
    assert text == read_text_beneath(workspace, "src/app.py", excluded=excluded, expired=_never)
    assert text == (b"print('hello')\n", 15)

    listing = _ok(
        handler,
        WorkspaceOperation.LIST_BENEATH,
        ListBeneathArguments(_HANDLE, "", excluded=(os.fspath(protected),)),
    )
    assert listing == list_beneath(workspace, "", excluded=excluded, expired=_never)
    names = [name for name, _directory in listing[0]]
    assert "src" in names and ".gitignore" not in names


def test_declared_tests_resolve_beneath_the_claimed_root(repository: Path, protected: Path) -> None:
    handler = _handler(repository, protected)
    location = f"{repository}/tests/test_app.py"
    expected = read_declared_test(location, excluded=(os.fspath(protected),))
    assert expected == b"def test_app():\n    pass\n"
    assert (
        _ok(
            handler,
            WorkspaceOperation.READ_DECLARED_TEST,
            ReadDeclaredTestArguments(_HANDLE + "/tests/test_app.py"),
        )
        == expected
    )
    assert (
        _ok(
            handler,
            WorkspaceOperation.READ_DECLARED_TEST,
            ReadDeclaredTestArguments(location),
        )
        == expected
    )
    assert _refused(
        handler,
        WorkspaceOperation.READ_DECLARED_TEST,
        ReadDeclaredTestArguments(_OTHER + "/tests/test_app.py"),
    ) == ("refused", "workspace_not_claimed")


def test_lstat_reports_only_outside_candidates(
    repository: Path, protected: Path, shared: Path
) -> None:
    handler = _handler(repository, protected)
    outside = f"{shared}/spec.md"
    paths = (
        outside,
        f"{repository}/tracked.txt",
        f"{protected}/vault.txt",
        f"{shared}/missing.md",
        f"{shared}/data/../spec.md",
    )
    facts = _ok(handler, WorkspaceOperation.LSTAT_CANDIDATES, LstatCandidatesArguments(paths))
    expected = LstatFacts.from_stat_result(os.lstat(outside))
    assert facts == (expected, None, None, None, None)
    assert stat.S_ISREG(facts[0].mode)


def test_a_spent_deadline_ends_a_metadata_read(
    repository: Path, protected: Path, shared: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = iter([0.0, 120.0])
    monkeypatch.setattr(agent_module, "time", SimpleNamespace(monotonic=lambda: next(clock)))
    handler = _handler(repository, protected)
    assert _refused(
        handler,
        WorkspaceOperation.LSTAT_CANDIDATES,
        LstatCandidatesArguments((f"{shared}/spec.md",)),
    ) == ("unavailable", "read_deadline")


# --- observation -----------------------------------------------------------------------------


def _open(handler: WorkspaceAgentHandler) -> str:
    handle = _ok(handler, WorkspaceOperation.OPEN_WORKSPACE, OpenWorkspaceArguments(_HANDLE))
    assert remote_workspace_handle_valid(handle)
    return handle


def test_observation_operations_equal_the_local_adapters(repository: Path, protected: Path) -> None:
    handler = _handler(repository, protected)
    _change(repository)
    opened = _open(handler)
    local = open_local_workspace(repository)

    state = _ok(
        handler,
        WorkspaceOperation.SUBJECT_STATE_CAPTURE,
        SubjectStateCaptureArguments(opened),
    )
    assert state == GitSubjectStateAdapter().capture(
        SubjectStateCaptureCommand(local, SubjectStateFormat.GIT_STRUCTURAL_V1)
    )

    changed = _ok(handler, WorkspaceOperation.LIST_CHANGED_PATHS, ListChangedPathsArguments(opened))
    assert changed == list_changed_relative_paths(local)
    assert "new.py" in changed and "ignored.log" not in changed

    inspected = _ok(
        handler,
        WorkspaceOperation.INSPECT,
        InspectArguments(opened, ("new.py", "tracked.txt")),
    )
    assert inspected == LocalWorkspaceInspectAdapter().inspect(
        WorkspaceInspectCommand(workspace=local, relative_paths=("new.py", "tracked.txt"))
    )


def test_opened_workspaces_are_bounded_and_unknown_handles_are_reported(
    repository: Path, protected: Path
) -> None:
    handler = _handler(repository, protected)
    first = _open(handler)
    for _ in range(8):
        _open(handler)
    assert _refused(
        handler, WorkspaceOperation.LIST_CHANGED_PATHS, ListChangedPathsArguments(first)
    ) == ("unavailable", "handle_unknown")


def test_opening_a_directory_without_git_reports_the_closed_limitation(
    tmp_path: Path, protected: Path
) -> None:
    plain = (tmp_path / "plain").resolve()
    plain.mkdir()
    handler = _handler(plain, protected)
    outcome, reason = _refused(
        handler, WorkspaceOperation.OPEN_WORKSPACE, OpenWorkspaceArguments(_HANDLE)
    )
    assert outcome == "unavailable"
    assert reason in {"not_git", "unsafe_root", "workspace_unavailable"}


def test_the_check_policy_is_read_as_its_exact_bytes(repository: Path, protected: Path) -> None:
    handler = _handler(repository, protected)
    assert _refused(
        handler, WorkspaceOperation.LOAD_CHECK_POLICY, WorkspaceOnlyArguments(_HANDLE)
    ) == ("unavailable", "policy_absent")

    (repository / ".finishup").mkdir()
    (repository / ".finishup" / "checks.toml").write_text(_POLICY, encoding="utf-8")
    read = _ok(handler, WorkspaceOperation.LOAD_CHECK_POLICY, WorkspaceOnlyArguments(_HANDLE))
    assert read == CheckPolicyRead("current", _POLICY.encode("utf-8"))

    (repository / ".yoetz").mkdir()
    (repository / ".yoetz" / "checks.toml").write_text(_POLICY, encoding="utf-8")
    assert _refused(
        handler, WorkspaceOperation.LOAD_CHECK_POLICY, WorkspaceOnlyArguments(_HANDLE)
    ) == ("unavailable", "policy_ambiguous")

    (repository / ".finishup" / "checks.toml").unlink()
    legacy = _ok(handler, WorkspaceOperation.LOAD_CHECK_POLICY, WorkspaceOnlyArguments(_HANDLE))
    assert legacy.location == "legacy"

    (repository / ".yoetz" / "checks.toml").write_text("format = 1\n", encoding="utf-8")
    assert _refused(
        handler, WorkspaceOperation.LOAD_CHECK_POLICY, WorkspaceOnlyArguments(_HANDLE)
    ) == ("unavailable", "policy_invalid")


def _echo_approval() -> ApprovedCheckApproval:
    argv = (_ECHO, "hello")
    return ApprovedCheckApproval(
        approval_id="echo",
        argv=argv,
        allow_network=False,
        timeout_seconds=10.0,
        approval_commitment=approval_commitment("echo", argv, allow_network=False),
    )


def test_an_approved_check_runs_as_the_local_runner_runs_it(
    repository: Path, protected: Path
) -> None:
    (repository / ".finishup").mkdir()
    (repository / ".finishup" / "checks.toml").write_text(_POLICY, encoding="utf-8")
    handler = _handler(repository, protected)
    opened = _open(handler)
    approval = _echo_approval()
    digest = "sha256:" + "a" * 64

    run = _ok(
        handler,
        WorkspaceOperation.RUN_APPROVED_CHECK,
        RunApprovedCheckArguments(opened, approval, digest, digest),
    )
    assert type(run) is ApprovedCheckRun
    captured: list[tuple[bytes, bool]] = []
    direct = ApprovedCheckRunner(
        {approval.approval_commitment: approval},
        sandbox=_ReadySandbox(),
        output_sink=lambda output, redacted: captured.append((output, redacted)),
    ).run(
        ApprovedCheckCommand(
            workspace=open_local_workspace(repository),
            approval=approval,
            subject_state_digest=digest,
            expected_subject_state_digest=digest,
        )
    )
    assert run.result.status is ApprovedCheckStatus.PASSED
    for name in (
        "status",
        "outcome",
        "exit_status",
        "output_digest",
        "output_bytes",
        "subject_state_digest",
        "approval_commitment",
    ):
        assert getattr(run.result, name) == getattr(direct, name)
    assert (run.output, run.output_redacted) == captured[-1] == (b"hello\n", False)

    stale = _ok(
        handler,
        WorkspaceOperation.RUN_APPROVED_CHECK,
        RunApprovedCheckArguments(opened, approval, digest, "sha256:" + "b" * 64),
    )
    assert stale.result.status is ApprovedCheckStatus.STALE
    assert stale.output is None


def test_a_check_the_repository_policy_does_not_approve_never_runs(
    repository: Path, protected: Path, tmp_path: Path
) -> None:
    marker = tmp_path / "ran"
    touch = shutil.which("touch", path=os.defpath) or "/usr/bin/touch"
    argv = (touch, os.fspath(marker))
    forged = ApprovedCheckApproval(
        approval_id="echo",
        argv=argv,
        allow_network=False,
        timeout_seconds=10.0,
        approval_commitment=approval_commitment("echo", argv, allow_network=False),
    )
    handler = _handler(repository, protected)
    opened = _open(handler)
    digest = "sha256:" + "a" * 64
    # No policy at all approves nothing.
    assert _refused(
        handler,
        WorkspaceOperation.RUN_APPROVED_CHECK,
        RunApprovedCheckArguments(opened, _echo_approval(), digest),
    ) == ("refused", "check_not_approved")
    # A policy that approves a different argv does not approve this one.
    (repository / ".finishup").mkdir()
    (repository / ".finishup" / "checks.toml").write_text(_POLICY, encoding="utf-8")
    assert _refused(
        handler,
        WorkspaceOperation.RUN_APPROVED_CHECK,
        RunApprovedCheckArguments(opened, forged, digest),
    ) == ("refused", "check_not_approved")
    assert not marker.exists()


# --- the reply itself ------------------------------------------------------------------------


def test_an_undeclared_operation_is_refused(repository: Path, protected: Path) -> None:
    handler = _handler(repository, protected, operations=("capture",))
    assert _refused(
        handler, WorkspaceOperation.READ_TASK_BASE, WorkspaceOnlyArguments(_HANDLE)
    ) == ("refused", "operation_not_declared")


def test_arguments_outside_the_codec_are_refused(repository: Path, protected: Path) -> None:
    handler = _handler(repository, protected)
    call = WorkspaceCall(
        kind="workspace_call",
        protocol_version="1.0",
        call_id=new_id(IdKind.CONTROL_RPC),
        service_instance_id=_SERVICE,
        service_generation="1",
        operation="read_task_base",
        arguments={"workspace": _HANDLE, "extra": True},  # pyright: ignore[reportArgumentType]
        deadline_ms=1_000,
    )
    reply = handler.answer(call, workspace_handle=_HANDLE)
    assert (reply.outcome, reply.reason, reply.result) == ("refused", "arguments_invalid", None)


def test_an_unexpected_fault_is_one_closed_reply_without_its_text(
    repository: Path, protected: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def explode(*_args: object, **_kwargs: object) -> object:
        raise RuntimeError(f"cannot read {repository}/secret.txt")

    monkeypatch.setattr(agent_module, "read_text_beneath", explode)
    handler = _handler(repository, protected)
    reply = _reply(
        handler, WorkspaceOperation.READ_TEXT_BENEATH, ReadTextBeneathArguments(_HANDLE, "a")
    )
    assert (reply.outcome, reply.reason, reply.result) == ("failed", "internal_error", None)
    assert "secret" not in repr(reply)


def test_reply_helper_builds_ok_and_closed_outcomes() -> None:
    call_id = new_id(IdKind.CONTROL_RPC)
    assert workspace_reply(call_id, None, {"a": 1}).outcome == "ok"
    assert workspace_reply(call_id, "agent_busy").outcome == "unavailable"
    assert workspace_reply(call_id, "workspace_not_claimed").outcome == "refused"
    assert workspace_reply(call_id, "internal_error").outcome == "failed"
    with pytest.raises(ValueError):
        workspace_reply(call_id, "not_a_reason")


def test_an_exclusion_closed_to_this_account_is_dropped_and_the_rest_kept(
    repository: Path, protected: Path, shared: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    closed = "/srv/finishup-server/state"
    stats: list[str] = []

    def stat(path: str) -> object:
        stats.append(path)
        if path == closed:
            raise PermissionError(13, "denied")
        if path == "/srv/missing":
            raise FileNotFoundError(2, "missing")
        return object()

    examinable = agent_module._examinable  # pyright: ignore[reportPrivateUsage]
    with pytest.MonkeyPatch.context() as patched:
        patched.setattr(agent_module, "os", SimpleNamespace(stat=stat))
        assert examinable(closed) is False
        assert examinable("/srv/missing") is True
        assert examinable("/srv/open") is True

    def open_here(path: str) -> bool:
        return path != closed

    monkeypatch.setattr(agent_module, "_examinable", open_here)
    seen: list[tuple[str, ...]] = []

    def capture(*_args: object, excluded: tuple[str, ...], **_kwargs: object) -> tuple[()]:
        seen.append(excluded)
        return ()

    monkeypatch.setattr(agent_module, "read_outside_inputs", capture)
    handler = _handler(repository, protected)
    _ok(
        handler,
        WorkspaceOperation.READ_OUTSIDE_INPUTS,
        ReadOutsideInputsArguments(
            (os.fspath(shared),), (f"{shared}/spec.md",), excluded=(_HANDLE, closed, "/srv/kept")
        ),
    )
    assert seen == [(os.fspath(repository), "/srv/kept", os.fspath(protected))]
