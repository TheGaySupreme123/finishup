"""The client workspace agent answers each catalog operation exactly as the local adapter would.

Every operation runs against a real temporary Git repository and is compared, after the catalog
round trip, with the same adapter called directly the way a local service calls it. The agent's
own confinements are exercised beside that: only its claimed workspace, outside reads only
beneath admitted roots and never into the workspace or FinishUP's own directories, approved
checks only from the repository's own policy, and closed reasons for everything else.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

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
from finishup.ports.workspace_inspect import (
    WorkspaceInspectCommand,
    WorkspaceInspectLimitation,
    WorkspaceInspectStatus,
)
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
    repository: Path,
    protected: Path,
    *,
    operations: Sequence[str] | None = None,
    folders: Sequence[Path | str] = (),
) -> WorkspaceAgentHandler:
    """A handler for ``repository``; ``folders`` stand for the client's admitted-folder record."""

    admitted = tuple(os.fspath(folder) for folder in folders)
    return WorkspaceAgentHandler(
        WorkspaceLocator(os.fspath(repository)),
        protected=(os.fspath(protected),),
        operations=operations,
        check_sandbox=_ReadySandbox(),
        outside_folders=lambda: admitted,
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
    handler = _handler(repository, protected, folders=(shared,))
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
    repository: Path,
    protected: Path,
    tmp_path: Path,
    tmp_path_factory: pytest.TempPathFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The owner admitted a root that holds the workspace and FinishUP's own state; the server
    # names no exclusion at all. The agent still reads neither. (HOME lives elsewhere here: a
    # folder that holds the home directory is never admitted.)
    monkeypatch.setenv("HOME", os.fspath(tmp_path_factory.mktemp("elsewhere-home")))
    root = os.fspath(tmp_path.resolve())
    handler = _handler(repository, protected, folders=(root,))
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
    # Even admitted on this client, FinishUP's own directories are never a read root.
    handler = _handler(repository, protected, folders=(protected,))
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


def test_a_declared_test_outside_the_claimed_workspace_is_refused(
    repository: Path, protected: Path, shared: Path
) -> None:
    """The server names a declared test's location with no admitted root (ADR-051 decision 5)."""

    handler = _handler(repository, protected)
    outside = f"{shared}/spec.md"
    # A local read of the same file succeeds: the refusal is the agent's confinement alone.
    assert read_declared_test(outside, excluded=(os.fspath(protected),)) == b"SPEC_MARKER\n"
    sibling = repository.parent / (repository.name + "-other")
    sibling.mkdir()
    (sibling / "test_x.py").write_text("def test_x():\n    pass\n", encoding="utf-8")
    for location in (
        outside,
        f"{sibling}/test_x.py",
        f"{repository.parent}/{repository.name.upper()}/tests/test_app.py",
        os.fspath(repository),
    ):
        assert _refused(
            handler,
            WorkspaceOperation.READ_DECLARED_TEST,
            ReadDeclaredTestArguments(location),
        ) == ("refused", "root_not_admitted"), location


def test_an_outside_root_is_read_only_beneath_a_folder_admitted_on_this_client(
    repository: Path,
    protected: Path,
    shared: Path,
    tmp_path_factory: pytest.TempPathFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The server's word that a root is admitted is not enough (ADR-051 decision 5)."""

    # HOME lives elsewhere, so the folder above ``shared`` may be admitted.
    monkeypatch.setenv("HOME", os.fspath(tmp_path_factory.mktemp("elsewhere-home")))

    root = os.fspath(shared)
    values = (f"{shared}/spec.md", f"{shared}/data/rows.csv")
    reads = (
        (WorkspaceOperation.READ_TEXT_BENEATH, ReadTextBeneathArguments(root, "spec.md")),
        (WorkspaceOperation.LIST_BENEATH, ListBeneathArguments(root, "")),
    )
    # A valid shape the local reader would read beneath, but nothing admitted here.
    assert read_text_beneath(root, "spec.md", excluded=(), expired=_never) is not None
    for folders in ((), (f"{shared}-other",), (f"{shared}/data",), (f"{shared.parent}/SHARED",)):
        handler = _handler(repository, protected, folders=folders)
        for operation, arguments in reads:
            assert _refused(handler, operation, arguments) == ("refused", "root_not_admitted")
        # A task-input read reads beneath the admitted roots only: here, none.
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
    # Admitted at the root itself, or above it: read as the local reader reads.
    for folders in ((shared,), (shared.parent,)):
        handler = _handler(repository, protected, folders=folders)
        assert _ok(handler, *reads[0]) == (b"SPEC_MARKER\n", 12)
        assert ("spec.md", False) in _ok(handler, *reads[1])[0]
    # A narrower folder admits the roots beneath it alone.
    narrow = _handler(repository, protected, folders=(f"{shared}/data",))
    assert _ok(
        narrow,
        WorkspaceOperation.READ_TEXT_BENEATH,
        ReadTextBeneathArguments(f"{shared}/data", "rows.csv"),
    ) == (b"a,b\n1,2\n", 8)


def test_a_task_input_read_skips_the_roots_not_admitted_here(
    repository: Path, protected: Path, shared: Path, tmp_path: Path
) -> None:
    other = (tmp_path / "other").resolve()
    other.mkdir()
    (other / "notes.md").write_text("OTHER_MARKER\n", encoding="utf-8")
    roots = (os.fspath(other), os.fspath(shared))
    values = (f"{other}/notes.md", f"{shared}/spec.md")
    handler = _handler(repository, protected, folders=(shared,))
    inputs = _ok(
        handler,
        WorkspaceOperation.READ_OUTSIDE_INPUTS,
        ReadOutsideInputsArguments(roots, values, limit=4),
    )
    assert [item.path for item in inputs] == [f"{shared}/spec.md"]
    snapshot = _ok(
        handler,
        WorkspaceOperation.SNAPSHOT_OUTSIDE_INPUTS,
        SnapshotOutsideInputsArguments(roots, values, limit=4, max_bytes=65_536, budget_ms=5_000),
    )
    assert [(row.path, row.text) for row in snapshot] == [(f"{shared}/spec.md", b"SPEC_MARKER\n")]
    # A root of a shape no owner could admit still refuses the whole call.
    assert _refused(
        handler,
        WorkspaceOperation.READ_OUTSIDE_INPUTS,
        ReadOutsideInputsArguments(("/etc", os.fspath(shared)), values, limit=4),
    ) == ("refused", "root_not_admitted")


def test_the_admitted_folders_are_read_on_every_call_and_fail_closed(
    repository: Path, protected: Path, shared: Path
) -> None:
    admitted: list[str] = [os.fspath(shared)]
    failing = False

    def folders() -> tuple[str, ...]:
        if failing:
            raise OSError("record_unreadable")
        return tuple(admitted)

    handler = WorkspaceAgentHandler(
        WorkspaceLocator(os.fspath(repository)),
        protected=(os.fspath(protected),),
        outside_folders=folders,
    )
    read = (
        WorkspaceOperation.READ_TEXT_BENEATH,
        ReadTextBeneathArguments(os.fspath(shared), "spec.md"),
    )
    assert _ok(handler, *read) == (b"SPEC_MARKER\n", 12)
    admitted.clear()  # 'server folders remove' takes effect at the next call
    assert _refused(handler, *read) == ("refused", "root_not_admitted")
    admitted.append(os.fspath(shared))
    failing = True  # a record that cannot be read admits nothing
    assert _refused(handler, *read) == ("refused", "root_not_admitted")
    failing = False
    # A recorded folder that holds the home directory, or of a shape no owner may admit, is
    # never used.
    admitted[:] = [os.path.expanduser("~"), "/etc", "relative"]
    assert _refused(
        handler,
        WorkspaceOperation.LIST_BENEATH,
        ListBeneathArguments(os.path.expanduser("~"), ""),
    ) == ("refused", "root_not_admitted")


def test_by_default_the_active_targets_own_record_admits(
    repository: Path, protected: Path, shared: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    asked: list[bool] = []

    def active() -> tuple[str, ...]:
        asked.append(True)
        return (os.fspath(shared),)

    monkeypatch.setattr(agent_module, "active_target_folders", active)
    handler = WorkspaceAgentHandler(
        WorkspaceLocator(os.fspath(repository)), protected=(os.fspath(protected),)
    )
    assert _ok(
        handler,
        WorkspaceOperation.READ_TEXT_BENEATH,
        ReadTextBeneathArguments(os.fspath(shared), "spec.md"),
    ) == (b"SPEC_MARKER\n", 12)
    assert asked == [True]


def test_a_declared_test_beneath_an_admitted_folder_is_read_as_locally(
    repository: Path, protected: Path, shared: Path
) -> None:
    """The local parity #1220 keeps, within what this client's owner admitted (ADR-051)."""

    (shared / ".hidden").mkdir()
    (shared / ".hidden" / "test_h.py").write_text("def test_h():\n    pass\n", encoding="utf-8")
    handler = _handler(repository, protected, folders=(shared,))
    assert _ok(
        handler,
        WorkspaceOperation.READ_DECLARED_TEST,
        ReadDeclaredTestArguments(f"{shared}/spec.md"),
    ) == read_declared_test(f"{shared}/spec.md", excluded=(os.fspath(protected),))
    # The adapter's own fences still hold beneath the folder: a hidden component reads nothing.
    assert (
        _ok(
            handler,
            WorkspaceOperation.READ_DECLARED_TEST,
            ReadDeclaredTestArguments(f"{shared}/.hidden/test_h.py"),
        )
        is None
    )
    sibling = shared.parent / (shared.name + "-other")
    sibling.mkdir()
    (sibling / "test_x.py").write_text("def test_x():\n    pass\n", encoding="utf-8")
    assert _refused(
        handler,
        WorkspaceOperation.READ_DECLARED_TEST,
        ReadDeclaredTestArguments(f"{sibling}/test_x.py"),
    ) == ("refused", "root_not_admitted")


def test_a_declared_test_spelled_through_a_root_owned_top_link_is_the_same_place(
    repository: Path, protected: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """macOS ``/tmp`` leads to ``/private/tmp``: the comparison walks the spelling the local read
    walks (``declared_test_top``), so it never falsely refuses an in-workspace test."""

    from finishup.adapters import task_input_read

    real_top = "/" + os.fspath(repository).split("/")[1]
    original = task_input_read.declared_test_top

    def walked(location: str) -> tuple[str, str] | None:
        # ``/alias`` stands for a root-owned link to the first component of the real path.
        first, _, rest = location[1:].partition("/")
        return (real_top, rest) if first == "alias" and rest else original(location)

    monkeypatch.setattr(task_input_read, "declared_test_top", walked)
    monkeypatch.setattr(agent_module, "declared_test_top", walked)
    aliased = "/alias" + os.fspath(repository)[len(real_top) :]
    expected = b"def test_app():\n    pass\n"
    # The location through the link, the claimed root resolved, as every client surface sends it.
    handler = _handler(repository, protected)
    assert (
        _ok(
            handler,
            WorkspaceOperation.READ_DECLARED_TEST,
            ReadDeclaredTestArguments(f"{aliased}/tests/test_app.py"),
        )
        == expected
    )
    # Beneath an admitted folder too: the folder is recorded resolved, the location is not.
    outside = _handler(repository.parent / "elsewhere", protected, folders=(repository,))
    assert (
        _ok(
            outside,
            WorkspaceOperation.READ_DECLARED_TEST,
            ReadDeclaredTestArguments(f"{aliased}/tests/test_app.py"),
        )
        == expected
    )


def test_no_agent_is_built_for_the_filesystem_root(protected: Path) -> None:
    with pytest.raises(ValueError, match="workspace_locator_path_invalid"):
        WorkspaceAgentHandler(WorkspaceLocator("/"), protected=(os.fspath(protected),))


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


def test_lstat_never_reports_what_the_local_candidate_rule_would_not_look_at(
    repository: Path, protected: Path, shared: Path
) -> None:
    """A server learns nothing of hidden, credential-named or system paths (ADR-051)."""

    handler = _handler(repository, protected)
    (shared / ".ssh").mkdir()
    (shared / ".ssh" / "id_ed25519").write_text("KEY\n", encoding="utf-8")
    (shared / "credentials").write_text("SECRET\n", encoding="utf-8")
    (shared / "deploy.pem").write_text("PEM\n", encoding="utf-8")
    refused = (
        f"{shared}/.ssh",
        f"{shared}/.ssh/id_ed25519",
        f"{shared}/credentials",
        f"{shared}/deploy.pem",
        "/proc/self/status",
        "/etc/hostname",
        "/",
    )
    for path in refused[:4]:
        assert os.path.lexists(path)
    facts = _ok(
        handler,
        WorkspaceOperation.LSTAT_CANDIDATES,
        LstatCandidatesArguments((*refused, f"{shared}/spec.md")),
    )
    assert facts[:-1] == (None,) * len(refused)
    assert facts[-1] == LstatFacts.from_stat_result(os.lstat(f"{shared}/spec.md"))


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


def test_inspect_reads_only_the_workspaces_own_changed_paths(
    repository: Path, protected: Path
) -> None:
    """A server cannot pick secrets to excerpt: ignored, unchanged and Git files stay unread."""

    (repository / ".gitignore").write_text("ignored.log\n.env\n*.key\n", encoding="utf-8")
    _git(repository, "add", ".gitignore")
    _git(repository, "commit", "--quiet", "-m", "ignore secrets")
    (repository / "deploy.pem").write_text("TRACKED_PEM\n", encoding="utf-8")
    _git(repository, "add", "deploy.pem")
    _git(repository, "commit", "--quiet", "-m", "track a pem")
    # Built from parts so the publication-boundary scanner sees no URI userinfo literal.
    credentialed_url = "https://" + "user:TOKEN123" + "@example.invalid/r"
    _git(repository, "config", "remote.origin.url", credentialed_url)
    _change(repository)
    (repository / ".env").write_text("AWS_SECRET=SUPERSECRET_ENV\n", encoding="utf-8")
    (repository / "config").mkdir()
    (repository / "config" / "master.key").write_text("MASTERKEY_SECRET\n", encoding="utf-8")
    (repository / "deploy.pem").write_text("CHANGED_PEM_SECRET\n", encoding="utf-8")
    handler = _handler(repository, protected)
    opened = _open(handler)

    secrets = (".env", "config/master.key", ".git/config", "deploy.pem", "tracked.txt.orig")
    rejected = _ok(handler, WorkspaceOperation.INSPECT, InspectArguments(opened, secrets))
    assert rejected.status is WorkspaceInspectStatus.REJECTED
    assert rejected.artifacts == ()
    assert rejected.limitations == (WorkspaceInspectLimitation.PATH_OUT_OF_SCOPE,)

    mixed = _ok(
        handler, WorkspaceOperation.INSPECT, InspectArguments(opened, ("new.py", ".env", "README"))
    )
    assert mixed.status is WorkspaceInspectStatus.PARTIAL
    assert [artifact.relative_path for artifact in mixed.artifacts] == ["new.py"]
    assert WorkspaceInspectLimitation.PATH_OUT_OF_SCOPE in mixed.limitations
    for result in (rejected, mixed):
        for marker in (b"SUPERSECRET", b"MASTERKEY", b"TOKEN123", b"PEM_SECRET"):
            assert all(marker not in artifact.excerpt for artifact in result.artifacts)
    # The workspace's own changed paths are inspected exactly as the local adapter does.
    changed = ("new.py", "tracked.txt")
    assert _ok(
        handler, WorkspaceOperation.INSPECT, InspectArguments(opened, changed)
    ) == LocalWorkspaceInspectAdapter().inspect(
        WorkspaceInspectCommand(workspace=open_local_workspace(repository), relative_paths=changed)
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


def _keyed_handler(repository: Path, protected: Path, key: bytes) -> WorkspaceAgentHandler:
    return WorkspaceAgentHandler(
        WorkspaceLocator(os.fspath(repository)),
        protected=(os.fspath(protected),),
        check_sandbox=_ReadySandbox(),
        opened_handle_key=key,
    )


def test_a_keyed_opened_handle_is_answered_by_another_agent_of_the_client(
    repository: Path, protected: Path
) -> None:
    """Several connections of one client serve a worktree; any of them answers its handle."""

    _change(repository)
    key = b"k" * 32
    opener = _keyed_handler(repository, protected, key)
    other = _keyed_handler(repository, protected, key)
    opened = _open(opener)
    # The same open gives the same keyed handle, for this root only.
    assert _open(opener) == opened
    assert _open(other) == opened
    fresh = _keyed_handler(repository, protected, key)
    changed = _ok(fresh, WorkspaceOperation.LIST_CHANGED_PATHS, ListChangedPathsArguments(opened))
    assert changed == list_changed_relative_paths(open_local_workspace(repository))
    # Without the key, or with another, the handle names nothing this agent opened.
    for stranger in (
        _handler(repository, protected),
        _keyed_handler(repository, protected, b"x" * 32),
    ):
        assert _refused(
            stranger, WorkspaceOperation.LIST_CHANGED_PATHS, ListChangedPathsArguments(opened)
        ) == ("unavailable", "handle_unknown")
    # A well-formed handle the key never made is refused, never opened.
    forged = "rws_" + "0" * 32
    assert _refused(
        fresh, WorkspaceOperation.LIST_CHANGED_PATHS, ListChangedPathsArguments(forged)
    ) == ("unavailable", "handle_unknown")


def test_a_keyed_handle_in_use_is_never_forgotten(repository: Path, protected: Path) -> None:
    """A verification keeps its handle while ingests open the workspace again and again."""

    _change(repository)
    handler = _keyed_handler(repository, protected, b"k" * 32)
    opened = _open(handler)
    for admitted_home_project in (True, False) * 8:
        _ok(
            handler,
            WorkspaceOperation.OPEN_WORKSPACE,
            OpenWorkspaceArguments(_HANDLE, admitted_home_project),
        )
    changed = _ok(handler, WorkspaceOperation.LIST_CHANGED_PATHS, ListChangedPathsArguments(opened))
    assert changed == list_changed_relative_paths(open_local_workspace(repository))


def test_a_handle_opened_on_one_connection_is_answered_on_a_newer_one(
    repository: Path, protected: Path
) -> None:
    """The hub routes a later call to the newest channel; that agent answers the handle."""

    import asyncio

    from finishup.service.workspace_hub import WorkspaceAgentHub, live_call_scope
    from finishup.service.workspace_routing import RoutedObservationWorkspace

    _change(repository)
    key = b"k" * 32
    older, newer = (_keyed_handler(repository, protected, key) for _ in range(2))
    answered: list[str] = []

    async def exercise() -> tuple[str, ...]:
        hub = WorkspaceAgentHub(inline_wait_seconds=1.0, background_wait_seconds=1.0)

        async def register(handler: WorkspaceAgentHandler, name: str) -> object:
            holder: list[Any] = []

            async def writer(call: WorkspaceCall) -> None:
                answered.append(name)
                reply = await asyncio.to_thread(handler.answer, call, workspace_handle=_HANDLE)
                hub.deliver(holder[0], reply)

            channel = await hub.register(
                handle=_HANDLE,
                declaration=handler.declaration,
                service_instance_id=_SERVICE,
                service_generation="1",
                writer=writer,
            )
            holder.append(channel)
            return channel

        first = await register(older, "older")
        await register(newer, "newer")
        access = RoutedObservationWorkspace(hub)
        with live_call_scope(cast(Any, first)):
            opened = await asyncio.to_thread(access.open, _HANDLE)
        # Background work later: the newest channel answers the handle the older one opened.
        return await asyncio.to_thread(access.list_changed, opened)

    changed = asyncio.run(exercise())
    assert answered == ["older", "newer"]
    assert changed == list_changed_relative_paths(open_local_workspace(repository))


def test_an_opened_handle_key_must_be_32_bytes(repository: Path, protected: Path) -> None:
    with pytest.raises(ValueError, match="opened_handle_key_invalid"):
        _keyed_handler(repository, protected, b"short")


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


def _trust_policy(repository: Path) -> None:
    """``finishup observe checks trust`` on this client: trust the policy's exact raw digest."""

    from finishup.adapters.integrations.observation_local import LocalObservationStore
    from finishup.application.observation_check_policy import load_observation_check_policy

    policy, _raw = load_observation_check_policy(repository)
    store = LocalObservationStore()
    store.trust_policy_digest(store.workspace_commitment(os.fspath(repository)), policy.raw_digest)


@pytest.fixture
def client_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """This client's own state (its observation store) in a private folder for the test."""

    state = tmp_path / "client-state"
    state.mkdir(mode=0o700)
    monkeypatch.setenv("XDG_STATE_HOME", os.fspath(state))
    return state


def test_an_approved_check_runs_as_the_local_runner_runs_it(
    repository: Path, protected: Path, client_state: Path
) -> None:
    (repository / ".finishup").mkdir()
    (repository / ".finishup" / "checks.toml").write_text(_POLICY, encoding="utf-8")
    _trust_policy(repository)
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


_SLEEP = shutil.which("sleep", path=os.defpath) or "/bin/sleep"


def _sleep_approval(timeout_seconds: float) -> tuple[ApprovedCheckApproval, str]:
    argv = (_SLEEP, "30")
    approval = ApprovedCheckApproval(
        approval_id="long",
        argv=argv,
        allow_network=False,
        timeout_seconds=timeout_seconds,
        approval_commitment=approval_commitment("long", argv, allow_network=False),
    )
    policy = (
        'format = "yoetz.approved-check-policy/1"\n\n'
        "[[checks]]\n"
        'id = "long"\n'
        f'argv = ["{_SLEEP}", "30"]\n'
        f"timeout_seconds = {int(timeout_seconds)}\n"
        "network = false\n"
    )
    return approval, policy


def test_a_check_longer_than_its_call_ends_as_a_timeout_the_server_still_receives(
    repository: Path, protected: Path, client_state: Path
) -> None:
    """A 300 s approval cannot outlast the transport's 300 s call: the run is cut, not lost."""

    import time

    approval, policy = _sleep_approval(300.0)
    (repository / ".finishup").mkdir()
    (repository / ".finishup" / "checks.toml").write_text(policy, encoding="utf-8")
    # Only a policy this client's owner trusted runs at all (ADR-051 decision 12).
    _trust_policy(repository)
    handler = _handler(repository, protected)
    opened = _open(handler)
    digest = "sha256:" + "a" * 64
    arguments = RunApprovedCheckArguments(opened, approval, digest, digest)
    # The call leaves 1.5 s past the reply reserve for the run itself.
    call = _call(WorkspaceOperation.RUN_APPROVED_CHECK, arguments, deadline_ms=16_500)
    started = time.monotonic()
    reply = handler.answer(call, workspace_handle=_HANDLE)
    elapsed = time.monotonic() - started
    assert (reply.outcome, reply.reason) == ("ok", None)
    spec = operation_spec(WorkspaceOperation.RUN_APPROVED_CHECK)
    assert spec is not None
    run = spec.decode_result(reply.result)
    assert run.result.status is ApprovedCheckStatus.TIMEOUT
    assert elapsed < 16.5  # answered inside the call's own deadline
    # With no time left past the reserve, nothing runs and the call says so.
    starved = _call(WorkspaceOperation.RUN_APPROVED_CHECK, arguments, deadline_ms=10_000)
    late = handler.answer(starved, workspace_handle=_HANDLE)
    assert (late.outcome, late.reason) == ("unavailable", "deadline_exceeded")


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


def test_a_policy_the_owner_did_not_trust_here_runs_nothing(
    repository: Path, protected: Path, tmp_path: Path, client_state: Path
) -> None:
    """ADR-051 decision 12: the client's own trust decides, whatever a server asks."""

    marker = tmp_path / "ran"
    touch = shutil.which("touch", path=os.defpath) or "/usr/bin/touch"
    argv = (touch, os.fspath(marker))
    approval = ApprovedCheckApproval(
        approval_id="mark",
        argv=argv,
        allow_network=False,
        timeout_seconds=10.0,
        approval_commitment=approval_commitment("mark", argv, allow_network=False),
    )
    policy = (
        'format = "yoetz.approved-check-policy/1"\n\n'
        "[[checks]]\n"
        'id = "mark"\n'
        f"argv = [{json.dumps(touch)}, {json.dumps(os.fspath(marker))}]\n"
        "network = false\n"
    )
    (repository / ".finishup").mkdir()
    (repository / ".finishup" / "checks.toml").write_text(policy, encoding="utf-8")
    handler = _handler(repository, protected)
    opened = _open(handler)
    digest = "sha256:" + "a" * 64
    run = RunApprovedCheckArguments(opened, approval, digest, digest)

    # The repository's policy approves the argv, but nobody trusted it on this client.
    assert _refused(handler, WorkspaceOperation.RUN_APPROVED_CHECK, run) == (
        "refused",
        "check_not_approved",
    )
    # Trust recorded for an earlier policy does not carry over to an edited one.
    (repository / ".finishup" / "checks.toml").write_text(_POLICY, encoding="utf-8")
    _trust_policy(repository)
    (repository / ".finishup" / "checks.toml").write_text(policy, encoding="utf-8")
    assert _refused(handler, WorkspaceOperation.RUN_APPROVED_CHECK, run) == (
        "refused",
        "check_not_approved",
    )
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


def test_an_injected_trust_source_is_asked_for_the_exact_policy_digest(
    repository: Path, protected: Path
) -> None:
    from finishup.application.observation_check_policy import load_observation_check_policy

    (repository / ".finishup").mkdir()
    (repository / ".finishup" / "checks.toml").write_text(_POLICY, encoding="utf-8")
    asked: list[str] = []

    def untrusted(digest: str) -> bool:
        asked.append(digest)
        return False

    handler = WorkspaceAgentHandler(
        WorkspaceLocator(os.fspath(repository)),
        protected=(os.fspath(protected),),
        check_sandbox=_ReadySandbox(),
        check_policy_trust=untrusted,
    )
    opened = _open(handler)
    digest = "sha256:" + "a" * 64
    assert _refused(
        handler,
        WorkspaceOperation.RUN_APPROVED_CHECK,
        RunApprovedCheckArguments(opened, _echo_approval(), digest, digest),
    ) == ("refused", "check_not_approved")
    policy, _raw = load_observation_check_policy(repository)
    assert asked == [policy.raw_digest]
