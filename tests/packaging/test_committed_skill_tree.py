"""The activated project skill must equal a real trusted-project skill install.

``.agents/skills/finishup`` is the Codex-discoverable tree for this repository. The adjacent plugin
source tree is not an activated plugin, so keeping only that generated tree current can leave fresh
Codex sessions reading stale guidance. These tests bind the committed activation tree, its managed
marker, and its canonical owners to the supported ``CodexSkillIntegration`` installer.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

import pytest

from finishup.adapters.integrations.codex_skill import (
    CodexSkillIntegration,
    build_managed_marker,
    load_packaged_skill_members,
    load_packaged_skill_source,
)
from finishup.domain.values import request_id
from finishup.ports.integrations import (
    HarnessId,
    IntegrationAction,
    IntegrationScope,
    IntegrationTarget,
    SkillApplyCommand,
    SkillPreviewCommand,
)

_REPO_ROOT: Final = Path(__file__).resolve().parents[2]
_COMMITTED_TREE: Final = _REPO_ROOT / ".agents/skills/finishup"
_CANONICAL_TREE: Final = _REPO_ROOT / "skills/codex/finishup"
_GUIDANCE_DIR: Final = _REPO_ROOT / "guidance"
_MARKER_NAME: Final = ".yoetz-install.json"


def _expected_tree() -> dict[str, bytes]:
    members = dict(load_packaged_skill_members())
    members[_MARKER_NAME] = build_managed_marker(
        load_packaged_skill_source(), IntegrationScope.TRUSTED_PROJECT
    )
    return members


def _tree(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }


def test_the_committed_activation_tree_exists() -> None:
    assert _COMMITTED_TREE.is_dir(), (
        ".agents/skills/finishup is missing; regenerate it with CodexSkillIntegration "
        "(replace_modified=True, allow_untested=True)"
    )


def test_the_committed_activation_tree_matches_packaged_members_and_marker() -> None:
    assert _tree(_COMMITTED_TREE) == _expected_tree(), (
        ".agents/skills/finishup has drifted from the supported skill installer output; regenerate "
        "the whole tree rather than editing its managed files or marker"
    )


def test_the_activated_skill_matches_canonical_owners() -> None:
    expected = _expected_tree()
    assert expected["SKILL.md"] == (_CANONICAL_TREE / "SKILL.md").read_bytes()
    assert expected["manifest.json"] == (_CANONICAL_TREE / "manifest.json").read_bytes()
    for relative_path, data in sorted(expected.items()):
        prefix = "references/"
        if not relative_path.startswith(prefix):
            continue
        assert data == (_GUIDANCE_DIR / relative_path.removeprefix(prefix)).read_bytes()


@pytest.mark.anyio
async def test_a_real_skill_install_reproduces_the_committed_activation_tree(
    tmp_path: Path,
) -> None:
    tmp_path.chmod(0o700)
    target = IntegrationTarget(IntegrationScope.TRUSTED_PROJECT, str(tmp_path))
    adapter = CodexSkillIntegration(allow_untested=True)
    operation_id = request_id("req_9f64ffb6-6b3f-49c5-893f-ebf2543df2f8")
    preview = await adapter.preview_skill(
        HarnessId.CODEX,
        SkillPreviewCommand(operation_id, target, IntegrationAction.INSTALL, False),
    )
    result = await adapter.install_skill(
        HarnessId.CODEX,
        SkillApplyCommand(
            operation_id,
            target,
            IntegrationAction.INSTALL,
            preview.preview_digest,
            True,
            False,
        ),
    )

    assert result.state_after.value == "installed_exact"
    assert _tree(tmp_path / ".agents/skills/finishup") == _tree(_COMMITTED_TREE)
