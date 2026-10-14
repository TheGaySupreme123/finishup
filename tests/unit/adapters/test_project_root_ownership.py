"""Every host's project-root check admits a root-owned project root for a non-root user (container
``/app``) exactly as ``project_root_admitted`` decides, and still refuses another user's directory.

The runner cannot create a root-owned directory, so the runner's own uid plays the superuser and the
process pretends to run as another account. Files Yoetz writes inside the project are still checked
against the running user; only the project root itself is judged by the project rule.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path

import pytest

from yoetz.adapters.integrations import (
    claude_code_integration,
    codex_marketplace,
    codex_plugin,
    codex_skill,
    cursor_project_mcp,
    portable_plugin,
)
from yoetz.config import foreign_write
from yoetz.ports.integrations import IntegrationScope, IntegrationTarget
from yoetz.ports.plugin_artifacts import ArtifactTarget

pytestmark = pytest.mark.skipif(not hasattr(os, "geteuid"), reason="POSIX ownership")


def _codex_skill(root: Path) -> None:
    codex_skill._validated_project(  # pyright: ignore[reportPrivateUsage]
        IntegrationTarget(IntegrationScope.TRUSTED_PROJECT, str(root))
    )
    codex_skill._skill_parent_identity(root)  # pyright: ignore[reportPrivateUsage]


def _codex_plugin(root: Path) -> None:
    codex_plugin._validated_project(  # pyright: ignore[reportPrivateUsage]
        IntegrationTarget(IntegrationScope.TRUSTED_PROJECT, str(root))
    )


def _codex_marketplace(root: Path) -> None:
    codex_marketplace._validated_project(  # pyright: ignore[reportPrivateUsage]
        IntegrationTarget(IntegrationScope.TRUSTED_PROJECT, str(root))
    )


def _portable(root: Path) -> None:
    portable_plugin._validate_project(ArtifactTarget(str(root)))  # pyright: ignore[reportPrivateUsage]


def _cursor(root: Path) -> None:
    with cursor_project_mcp._directory(root, project=True):  # pyright: ignore[reportPrivateUsage]
        pass


def _claude(root: Path) -> None:
    claude_code_integration._safe_existing_ancestor(  # pyright: ignore[reportPrivateUsage]
        root, project=True
    )


CHECKS: dict[str, Callable[[Path], None]] = {
    "codex_skill": _codex_skill,
    "codex_plugin": _codex_plugin,
    "codex_marketplace": _codex_marketplace,
    "portable_plugin": _portable,
    "cursor_project_mcp": _cursor,
    "claude_code": _claude,
}


def _project(tmp_path: Path, mode: int) -> Path:
    root = tmp_path.resolve() / "app"
    root.mkdir()
    root.chmod(mode)
    return root


@pytest.mark.parametrize("name", sorted(CHECKS))
@pytest.mark.parametrize("mode", [0o755, 0o1777])
def test_superuser_owned_project_root_is_admitted_for_a_non_root_user(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str, mode: int
) -> None:
    root = _project(tmp_path, mode)
    real = os.geteuid()
    monkeypatch.setattr(foreign_write, "_SUPERUSER_UID", real)
    monkeypatch.setattr(os, "geteuid", lambda: real + 1)

    CHECKS[name](root)


@pytest.mark.parametrize("name", sorted(CHECKS))
@pytest.mark.parametrize(("mode", "owner"), [(0o755, "other"), (0o777, "superuser")])
def test_other_owner_or_shared_project_root_is_still_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str, mode: int, owner: str
) -> None:
    root = _project(tmp_path, mode)
    real = os.geteuid()
    monkeypatch.setattr(foreign_write, "_SUPERUSER_UID", real if owner == "superuser" else real + 7)
    monkeypatch.setattr(os, "geteuid", lambda: real + 1)

    with pytest.raises(Exception) as caught:  # noqa: PT011 - each host raises its own typed error
        CHECKS[name](root)
    assert "target_unsafe" in repr(caught.value) or "TARGET_UNSAFE" in repr(caught.value)
