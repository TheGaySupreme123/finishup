"""#1161: HOME selection is explicit; project reads never include home host/credential state."""

from __future__ import annotations

from pathlib import Path

import pytest

from finishup.adapters.git_change_capture import GitChangeCaptureAdapter
from finishup.adapters.git_subject_state import GitSubjectStateAdapter, open_local_workspace
from finishup.adapters.task_input_read import list_beneath, read_text_beneath
from finishup.adapters.workspace_binding import (
    canonical_workspace_locator,
    resolve_workspace_locator,
)
from finishup.application.check_change import requested_output_states
from finishup.config.home_project import home_project_scope
from finishup.ports.change_capture import ChangeCaptureUnavailable, CheckWorkspaceSource
from finishup.ports.subject_state import (
    SubjectStateCaptureCommand,
    SubjectStateFormat,
    SubjectStateStatus,
)
from unit.adapters.test_requested_path_probe import (
    _git,  # pyright: ignore[reportPrivateUsage]
    _projection,  # pyright: ignore[reportPrivateUsage]
    _repository,  # pyright: ignore[reportPrivateUsage]
)

_PRIVATE = (
    ".codex/auth.json",
    ".claude/projects/session.json",
    ".cursor/state.json",
    ".codex-testing/state.json",
    ".claude-testing/state.json",
    ".t3/sessions/session.json",
    ".ssh/config",
    ".aws/config",
    ".config/finishup/state.json",
    ".local/share/finishup/state.json",
    ".cache/host/session.json",
    ".agents/plugins/finishup/plugin.json",
    ".agents/skills/finishup/SKILL.md",
    ".agents/plugins/yoetz/plugin.json",
    "Library/Application Support/finishup/state.json",
    "AppData/host/session.json",
    "auth.json",
    "nested/auth.json",
    ".claude.json.backup",
    ".gitconfig",
    ".bash_history",
    "credentials.json",
    "nested/id_ed25519",
    ".env.private",
    "nested/service.pem",
)


def _home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = _repository(tmp_path).resolve()
    monkeypatch.setenv("HOME", str(root))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    return root


@pytest.mark.parametrize("host", ("codex", "claude_code", "cursor"))
def test_home_stays_default_denied_and_exact_host_opt_in_allows_the_git_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, host: str
) -> None:
    root = _home(tmp_path, monkeypatch)
    assert canonical_workspace_locator(root) is None
    with pytest.raises(ValueError, match="unsafe_root"):
        open_local_workspace(root)
    with home_project_scope(root):
        assert canonical_workspace_locator(root) == str(root), host
        # The three hosts' existing locator lanes converge on the same selected root.
        env = {"HOME": str(root)}
        payload = {"workspace_roots": [str(root)]} if host == "cursor" else None
        assert resolve_workspace_locator(str(root), payload=payload, env=env) == str(root)
        open_local_workspace(root)
        assert GitChangeCaptureAdapter().probe_requested_paths(str(root), ("kept.txt",))[0].exists
    with pytest.raises(ValueError, match="unsafe_root"):
        open_local_workspace(root)


def test_admitted_service_locator_works_without_the_host_process_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _home(tmp_path, monkeypatch)
    adapter = GitChangeCaptureAdapter(admitted_home_project=True)
    base = adapter.read_task_base(str(root))
    (root / "kept.txt").write_text("repaired answer\n")
    (root / "new.txt").write_text("new answer\n")
    (root / "gone.txt").unlink()
    _git(root, "add", "--", "kept.txt", "gone.txt")
    _git(
        root,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
        "commit",
        "-qm",
        "repair",
    )
    change = adapter.capture(str(root), base, input_paths=(".gitignore",))
    assert b"repaired answer" in change.text and b"new answer" in change.text
    assert {entry.path for entry in adapter.capture_metadata(str(root), base).entries} == {
        "kept.txt",
        "gone.txt",
        "new.txt",
    }
    assert any(item.path == ".gitignore" for item in change.inputs)
    (root / "subdir").mkdir()
    # A subdirectory without its own repository may not silently opt its HOME ancestor in.
    with pytest.raises(ChangeCaptureUnavailable, match="unsafe_root"):
        adapter.capture(str(root / "subdir"), base)


@pytest.mark.anyio
async def test_home_output_verification_uses_real_change_and_ignore_facts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _home(tmp_path, monkeypatch)
    adapter = GitChangeCaptureAdapter(admitted_home_project=True)
    base = adapter.read_task_base(str(root))
    (root / "answer.txt").write_text("answer\n")
    (root / "kept.txt").write_text("changed\n")
    (root / "gone.txt").unlink()
    (root / "checkpoints").mkdir()
    (root / "checkpoints/model.pt").write_bytes(b"ignored")
    outputs = ("answer.txt", "kept.txt", "gone.txt", "missing.txt", "checkpoints/model.pt")
    states = await requested_output_states(
        projection=_projection(*outputs),
        capture=adapter.capture_metadata(str(root), base),
        source=CheckWorkspaceSource(str(root), "hmac-sha256:" + "a" * 64),
        port=adapter,
        request_id="req_00000000-0000-4000-8000-000000000003",
    )
    one, two, deleted, missing, ignored = states.values()
    assert one.location == two.location == "inside"
    assert one.exists and one.changed and two.exists and two.changed
    assert deleted.deleted and deleted.exists is False
    assert missing.exists is False and ignored.ignored is True


@pytest.mark.parametrize("tracked", (False, True))
def test_home_state_never_enters_change_inputs_counts_outputs_or_structural_capture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tracked: bool
) -> None:
    root = _home(tmp_path, monkeypatch)
    for relative in _PRIVATE:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("private canary before\n")
    if tracked:
        _git(root, "add", "--force", "--", *_PRIVATE)
        _git(
            root,
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "state fixture",
        )
    adapter = GitChangeCaptureAdapter(admitted_home_project=True)
    base = adapter.read_task_base(str(root))
    handle = open_local_workspace(root, admitted_home_project=True)
    command = SubjectStateCaptureCommand(handle, SubjectStateFormat.GIT_STRUCTURAL_V1)
    before = GitSubjectStateAdapter().capture(command)
    assert before.status is SubjectStateStatus.CAPTURED
    for relative in _PRIVATE:
        (root / relative).write_text("private canary after\n")
    # Host shims/sockets/links under excluded state cannot make the project unsafe.
    (root / ".codex/shim").symlink_to(root / "kept.txt")
    after = GitSubjectStateAdapter().capture(command)
    assert after.status is SubjectStateStatus.CAPTURED
    assert after.subject_state == before.subject_state
    change = adapter.capture(str(root), base, input_paths=_PRIVATE)
    assert b"private canary" not in change.text and not change.inputs
    assert not adapter.capture_metadata(str(root), base).entries
    counts = adapter.count_change_lines(str(root), base.commit, _PRIVATE)
    assert counts.changed == () and all(value is None for value in counts.base_lines)
    assert all(
        probe.exists is None and probe.ignored is None
        for probe in adapter.probe_requested_paths(str(root), _PRIVATE)
    )
    assert all(
        read_text_beneath(str(root), name, excluded=(), expired=lambda: False) is None
        for name in _PRIVATE
    )
    listing = list_beneath(str(root), "", excluded=(), expired=lambda: False)
    assert listing is not None
    names = {name for name, _directory in listing[0]}
    assert not names.intersection({"Library", "AppData", "auth.json", "credentials.json"})


def test_filesystem_root_is_refused_even_when_home_and_admitted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HOME", "/")
    with home_project_scope(Path("/")), pytest.raises(ValueError, match="unsafe_root"):
        open_local_workspace(Path("/"), admitted_home_project=True)


def test_home_public_paths_keep_normal_hidden_project_changes_and_link_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _home(tmp_path, monkeypatch)
    adapter = GitChangeCaptureAdapter(admitted_home_project=True)
    base = adapter.read_task_base(str(root))
    (root / ".github/workflows").mkdir(parents=True)
    (root / ".github/workflows/check.yml").write_text("name: project check\n")
    (root / ".codex").mkdir()
    (root / ".codex/private.txt").write_text("private link canary\n")
    (root / "link.txt").symlink_to(root / ".codex/private.txt")
    change = adapter.capture(str(root), base)
    assert b"project check" in change.text and b"private link canary" not in change.text
    (probe,) = adapter.probe_requested_paths(str(root), ("link.txt",))
    # lstat may report the link's own existence, but supplies no target size or content.
    assert probe.exists is True and probe.size_bytes is None
    assert read_text_beneath(str(root), "link.txt", excluded=(), expired=lambda: False) is None


def test_home_exclusions_do_not_change_ordinary_project_roots(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _repository(tmp_path).resolve()
    home = tmp_path / "different-home"
    home.mkdir(mode=0o700)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    (root / "Library").mkdir()
    (root / "Library/source.txt").write_text("ordinary source library\n")
    adapter = GitChangeCaptureAdapter()
    change = adapter.capture(str(root), None)
    assert b"ordinary source library" in change.text
    assert read_text_beneath(str(root), "Library/source.txt", excluded=(), expired=lambda: False)
