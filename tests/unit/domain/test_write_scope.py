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
from finishup.domain.write_scope import (
    classify_write_path,
    docs_artifact_name,
    edit_write_scope,
    finishup_artifact_name,
    finishup_tree_overlap,
    without_docs_scope,
)
from synthetic_paths import LINUX_HOME


def _inside(path: str) -> bool:
    return path == "/app" or path.startswith("/app/")


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/app/solve.py", "workspace"),
        ("/app/src/cache/engine.py", "workspace"),
        ("/app/build/lib/generated.py", "notes"),
        ("/app/tests/fixtures/run.log", "workspace"),
        ("/app/output/flight_plan.json", "workspace"),
        # n7 RC2: a Markdown file outside test and data directories is project documentation;
        # a declared output with that name keeps counting in the kernel (``task_facts``).
        ("/app/DATA_RECOVERY.md", "docs"),
        ("relative/x.py", "workspace"),
        ("/tmp/solve_remap.py", "scratch"),
        ("/var/tmp/x", "scratch"),
        # Owner E: logs are notes; an explicitly declared output still overrides the exemption.
        ("/app/run.log", "notes"),
        ("/app/finishup_exporter.py", "workspace"),
        ("/app/finishup_receipt.md", "yoetz_owned"),
        ("/app/output/finishup_receipt.json", "yoetz_owned"),
        ("/app/.agents/skills/finishup/SKILL.md", "yoetz_owned"),
        ("/srv/state/finishup/ledger.sqlite", "yoetz_owned"),
        # Legacy receipt names and packaged trees an earlier install wrote stay owned (ADR-048).
        ("/app/yoetz_exporter.py", "workspace"),
        ("/app/yoetz_receipt.md", "yoetz_owned"),
        ("/app/output/yoetz-export.json", "yoetz_owned"),
        ("/app/.agents/skills/yoetz/SKILL.md", "yoetz_owned"),
        ("/app/.agents/plugins/yoetz/.mcp.json", "yoetz_owned"),
        ("/app/.agents/plugins/finishup/.mcp.json", "yoetz_owned"),
        ("/app/.agents/skills/yoetz-notes/SKILL.md", "workspace"),
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


def test_legacy_trees_overlap_like_the_finishup_trees() -> None:
    """A declared deliverable in either spelling of the packaged trees is the work (ADR-048)."""

    assert finishup_tree_overlap(".agents/skills/yoetz/SKILL.md")
    assert finishup_tree_overlap(".agents/plugins/finishup")
    assert not finishup_tree_overlap(".agents/skills/yoetz-extra/SKILL.md")
    assert finishup_artifact_name("out/yoetz_receipt.json")
    assert finishup_artifact_name("out/finishup_receipt.json")
    assert not finishup_artifact_name("out/receipt.json")


def test_a_workspace_under_a_temporary_root_is_still_the_workspace() -> None:
    assert classify_write_path("/tmp/work/a.py", workspace="/tmp/work", inside=True) == "workspace"
    assert classify_write_path("/tmp/work/a.log", workspace="/tmp/work", inside=True) == "notes"
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


# --- n7 RC2(c): project documentation is its own class (#1106) ---------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "/app/README.md",
        "README",
        "docs/guide.md",
        "CHANGELOG",
        "CHANGES.rst",
        "api.rst",
        "pkg/README.md",
        "README.ja.md",
        "LICENSE-MIT",
        "CONTRIBUTING.md",
        "docs/index.adoc",
        "docs/tests.md",  # a data word in the file name, not a directory, is not data
    ],
)
def test_project_docs_are_docs(path: str) -> None:
    inside = _inside(path) if path.startswith("/") else None
    assert docs_artifact_name(path)
    assert classify_write_path(path, workspace="/app", inside=inside) == "docs"


@pytest.mark.parametrize(
    "path",
    [
        "tests/fixtures/a.md",
        "prompts/system.md",
        "data/x.md",
        "src/app/templates/email.md",
        "__snapshots__/view.md",
        ".agents/skills/project/SKILL.md",
        ".claude/commands/review.md",
        "spec/expected.md",
    ],
)
def test_doc_extensions_under_test_or_data_dirs_count(path: str) -> None:
    # A declared output so named still turns the exemption off: the declared-path answer is wider.
    assert docs_artifact_name(path)
    assert classify_write_path(path, workspace="/app", inside=None) == "workspace"
    assert classify_write_path(f"/app/{path}", workspace="/app", inside=True) == "workspace"


@pytest.mark.parametrize(
    "workspace",
    [
        f"{LINUX_HOME}/u/repo/.claude/worktrees/feat",
        f"{LINUX_HOME}/u/.cursor/worktrees/repo/abc",
        f"{LINUX_HOME}/u/.codex/worktrees/abc/repo",
        "/srv/data/repo",
        "/work/tests/repo",
    ],
)
def test_data_directories_are_read_inside_the_workspace_only(workspace: str) -> None:
    """A host-managed worktree, or a workspace below a ``data`` folder, is not data (#1106 r1)."""

    for path in ("docs/guide.md", "api.rst", "pkg/notes/design.adoc"):
        absolute = f"{workspace}/{path}"
        assert classify_write_path(absolute, workspace=workspace, inside=True) == "docs"
        assert classify_write_path(path, workspace=workspace, inside=None) == "docs"
    assert (
        classify_write_path(f"{workspace}/tests/x.md", workspace=workspace, inside=True)
        == "workspace"
    )


def test_an_absolute_doc_extension_without_a_root_is_an_ordinary_edit() -> None:
    # The Codex session stream knows no workspace root: only a conventional name decides there.
    assert (
        classify_write_path("/srv/data/repo/guide.md", workspace=None, inside=None) == "workspace"
    )
    # A conventional name decides without a root, unless a directory on the whole path is data
    # (``/srv/data``): with no root to strip, a workspace there only loses the exemption.
    assert (
        classify_write_path(f"{LINUX_HOME}/u/repo/README.md", workspace=None, inside=None) == "docs"
    )
    assert (
        classify_write_path("/srv/data/repo/README.md", workspace=None, inside=None) == "workspace"
    )
    assert classify_write_path("../data/guide.md", workspace="/app", inside=None) == "workspace"
    assert _file_change_write_scope({f"{LINUX_HOME}/u/repo/docs/a.md": {}}) is None
    assert _file_change_write_scope({f"{LINUX_HOME}/u/repo/README.md": {}}) == "docs"


@pytest.mark.parametrize(
    "path",
    [
        "requirements.txt",
        "notes.txt.py",
        "history.py",
        "news.py",
        "changes.json",
        "x.txt",
        # Extensionless script names that only look like documentation (#1106 r1).
        "bin/security-scan",
        "scripts/history",
        "tools/news",
        "news",
        "CHANGES",
        "Security",
        "bin/readme-check",
        "contributing",
    ],
)
def test_txt_and_code_are_never_docs_by_name_or_extension(path: str) -> None:
    assert not docs_artifact_name(path)
    assert classify_write_path(path, workspace="/app", inside=None) == "workspace"


@pytest.mark.parametrize(
    "path", ["LICENSE", "LICENSE-APACHE", "LICENCE_MIT", "COPYING", "NOTICE", "AUTHORS", "README"]
)
def test_extensionless_docs_are_only_the_unambiguous_names(path: str) -> None:
    assert docs_artifact_name(path)
    assert classify_write_path(path, workspace="/app", inside=None) == "docs"


def test_notes_win_over_docs_and_outside_stays_outside() -> None:
    assert classify_write_path("/app/NOTES.md", workspace="/app", inside=True) == "notes"
    assert classify_write_path("/app/todo.md", workspace="/app", inside=True) == "notes"
    assert (
        classify_write_path("/opt/lib/README.md", workspace="/app", inside=False)
        == "outside_workspace"
    )
    assert classify_write_path("/tmp/README.md", workspace="/app", inside=False) == "scratch"


@pytest.mark.parametrize(
    ("classes", "scope"),
    [
        (("docs",), "docs"),
        (("docs", "docs"), "docs"),
        (("docs", "workspace"), None),
        (("docs", "notes"), None),
        (("docs", "outside_workspace"), "outside_workspace"),
    ],
)
def test_edit_write_scope_names_docs_only_alone(
    classes: tuple[str, ...], scope: str | None
) -> None:
    assert edit_write_scope(classes) == scope  # type: ignore[arg-type]


def test_codex_stream_file_change_names_docs() -> None:
    assert _file_change_write_scope({"README.md": {"type": "update"}}) == "docs"
    assert _file_change_write_scope([{"path": "docs/a.md"}, {"path": "CHANGELOG.md"}]) == "docs"
    assert _file_change_write_scope({"README.md": {}, "src/a.py": {}}) is None


# --- #1106 r2: extensionless names, names in data directories, and the skew fallback ----------


@pytest.mark.parametrize(
    "path",
    [
        "bin/license-check",
        "scripts/notice-gen",
        "tools/license_scan",
        "copying-helper",
        "license-check",
        "bin/license",
        "bin/readme",
        "bin/changelog",
        "scripts/authors",
        "tests/fixtures/CHANGELOG.md",
        "tests/data/README.md",
        "tests/snapshots/README.md",
        "fixtures/LICENSE",
        "tests/fixtures/news.txt",
        "src/pkg/data/history.txt",
        "golden/out.md",
        "goldens/README.md",
        "expected/out.md",
        "src/pkg/resources/help.md",
    ],
)
def test_program_and_data_names_are_not_docs(path: str) -> None:
    """correctness-r2-3 / goal-r2-3: a script named like documentation, and documentation a test
    reads as data, keep counting as ordinary edits."""

    assert classify_write_path(path, workspace="/app", inside=None) == "workspace"
    assert classify_write_path(f"/app/{path}", workspace="/app", inside=True) == "workspace"


@pytest.mark.parametrize(
    "path",
    [
        "LICENSE",
        "LICENCE",
        "COPYING",
        "NOTICE",
        "LICENSE-MIT",
        "LICENSE-APACHE",
        "LICENSE-APACHE-2.0",
        "LICENSE_BSD-3-Clause",
        "COPYING-GPL-3.0-or-later",
        "LICENSE-THIRD-PARTY",
        "vendor/lib/LICENSE",
        "README",
        "pkg/CHANGELOG",
        "scripts/README.md",  # an extension is documentation in a program directory too
    ],
)
def test_conventional_extensionless_names_are_docs(path: str) -> None:
    assert classify_write_path(path, workspace="/app", inside=None) == "docs"


def test_without_docs_scope_records_the_older_class() -> None:
    assert without_docs_scope("docs", shell=True) == "workspace"
    assert without_docs_scope("docs", shell=False) is None
    for scope in ("notes", "workspace", "outside_workspace", None):
        assert without_docs_scope(scope, shell=True) == scope
