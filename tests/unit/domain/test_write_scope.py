"""Write classification for the finer stale rule (ADR-042, tb4n2 R4, issue #1018)."""

from __future__ import annotations

import pytest

from finishup.adapters.integrations.codex_session_stream import (
    _file_change_write_scope,  # pyright: ignore[reportPrivateUsage]
)
from finishup.application.observation_materialize import (
    _action_kind,  # pyright: ignore[reportPrivateUsage]
)
from finishup.domain.events import ActionKind
from finishup.domain.write_scope import classify_write_path, edit_write_scope


def _inside(path: str) -> bool:
    return path == "/app" or path.startswith("/app/")


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/app/solve.py", "workspace"),
        ("/app/output/flight_plan.json", "workspace"),
        ("/app/DATA_RECOVERY.md", "workspace"),
        ("relative/x.py", "workspace"),
        ("/tmp/solve_remap.py", "scratch"),
        ("/var/tmp/x", "scratch"),
        # A log inside the workspace may be a deliverable: it counts (Codex review round 1).
        ("/app/run.log", "workspace"),
        ("/app/finishup_exporter.py", "workspace"),
        ("/app/finishup_receipt.md", "yoetz_owned"),
        ("/app/output/finishup_receipt.json", "yoetz_owned"),
        ("/app/.agents/skills/finishup/SKILL.md", "yoetz_owned"),
        ("/srv/state/finishup/ledger.sqlite", "yoetz_owned"),
        ("/usr/lib/python3/site-packages/lightning/x.py", "outside_workspace"),
        ("/opt/logs/x.log", "outside_workspace"),
        ("/tmp/../etc/passwd", "outside_workspace"),
    ],
)
def test_classify_write_path(path: str, expected: str) -> None:
    inside = _inside(path) if path.startswith("/") else None
    assert (
        classify_write_path(
            path, workspace="/app", inside=inside, owned_roots=("/srv/state/finishup",)
        )
        == expected
    )


def test_a_workspace_under_a_temporary_root_is_still_the_workspace() -> None:
    assert classify_write_path("/tmp/work/a.py", workspace="/tmp/work", inside=True) == "workspace"
    assert classify_write_path("/tmp/work/a.log", workspace="/tmp/work", inside=True) == "workspace"
    # Without a workspace root nothing is scratch: `/tmp/project` may be the workspace itself.
    assert classify_write_path("/tmp/project/core.py", workspace=None, inside=None) == "workspace"


@pytest.mark.parametrize(
    ("classes", "scope"),
    [
        ((), None),
        (("workspace",), None),
        (("scratch",), "scratch"),
        # Codex review round 3: a mix keeps counting (precedence is per class).
        (("scratch", "yoetz_owned"), None),
        (("scratch", "workspace"), None),
        (("scratch", "outside_workspace"), "outside_workspace"),
        (("workspace", "outside_workspace"), "outside_workspace"),
    ],
)
def test_edit_write_scope_counts_any_real_path(classes: tuple[str, ...], scope: str | None) -> None:
    assert edit_write_scope(classes) == scope  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("tool", "kind"),
    [
        ("mcp__finishup__check", ActionKind.OTHER),
        ("mcp__finishup__publish_work", ActionKind.OTHER),
        ("mcp__plugin_finishup_finishup__receipt", ActionKind.OTHER),
        ("mcp__fs__edit_file", ActionKind.EDIT),
        ("apply_patch", ActionKind.EDIT),
        ("file_change", ActionKind.EDIT),
        ("Bash", ActionKind.COMMAND),
    ],
)
def test_finishup_mcp_tools_are_never_edits_or_commands(tool: str, kind: ActionKind) -> None:
    assert _action_kind(tool) is kind


def test_codex_stream_file_change_names_only_non_counting_scopes() -> None:
    # Rollout mapping form and `codex exec --json` list form.
    # The stream knows no workspace root, so a temp path is never exempt there.
    assert _file_change_write_scope({"/tmp/a.py": {"type": "add"}}) is None
    assert _file_change_write_scope([{"path": "/app/finishup_receipt.md"}]) == "yoetz_owned"
    assert _file_change_write_scope({"/app/cracker.py": {"type": "update"}}) is None
    assert (
        _file_change_write_scope({"/tmp/a.py": {"type": "add"}, "/app/b.py": {"type": "add"}})
        is None
    )
    assert _file_change_write_scope({"/tmp/a": {"type": "update", "move_path": "/app/a"}}) is None
    assert _file_change_write_scope(None) is None
    assert _file_change_write_scope({}) is None


def test_only_fixed_temp_roots_are_scratch(monkeypatch: pytest.MonkeyPatch) -> None:
    """Codex review round 2: a custom TMPDIR claims no outside write but is never exempt."""

    monkeypatch.setenv("TMPDIR", "/scratch-tmp")
    assert (
        classify_write_path("/scratch-tmp/out.json", workspace="/app", inside=False) == "workspace"
    )
    assert classify_write_path("/tmp/x.py", workspace="/app", inside=False) == "scratch"
