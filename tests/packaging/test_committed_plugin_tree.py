"""The plugin tree committed at ``.agents/plugins/finishup/`` must equal a real install.

That tree is a generated artifact: the output of ``install_plugin`` at
``IntegrationScope.TRUSTED_PROJECT``, committed so a contributor who clones this repository and
runs Codex in it gets the finishup skill, MCP server, and hooks for working on *this* repository. It
is deliberately absent from the sdist and the wheel -- package users install their own copy.

Because nothing regenerated it, it drifted. The consent-security change that landed in
``guidance/agent-instructions.md`` never reached the committed copy, so for several commits every
contributor's Codex agent read superseded instructions telling it to satisfy a confirmation phrase
it could see -- the exact pattern that change removed. The packaged tree was correct throughout;
only this checked-in install was stale, and no gate compared them.

``README.md`` states guidance is owned once under ``guidance/`` and shipped byte-identically
everywhere. These cases are what make that claim falsifiable for this surface.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from pathlib import Path
from typing import Final, cast

import pytest

from finishup.adapters.integrations.codex_plugin import (
    PLUGIN_ROOT,
    install_plugin,
    render_plugin_tree,
)
from finishup.ports.integrations import IntegrationScope, IntegrationTarget
from finishup.protocol.canonical import JsonValue, canonical_digest, strict_json_parse

_REPO_ROOT: Final = Path(__file__).resolve().parents[2]
_COMMITTED_TREE: Final = _REPO_ROOT / PLUGIN_ROOT
_MARKER_NAME: Final = ".yoetz-plugin-install.json"
_GUIDANCE_DIR: Final = _REPO_ROOT / "guidance"
_REFERENCES_PREFIX: Final = "skills/finishup/references/"


def _rendered() -> dict[str, bytes]:
    return render_plugin_tree()


def test_the_committed_tree_exists() -> None:
    assert _COMMITTED_TREE.is_dir(), (
        f"{PLUGIN_ROOT} is missing; regenerate it with install_plugin "
        "(replace_modified=True, allow_untested=True)"
    )


@pytest.mark.parametrize("relative_path", sorted(_rendered()))
def test_every_rendered_member_is_committed_byte_for_byte(relative_path: str) -> None:
    expected = _rendered()[relative_path]
    path = _COMMITTED_TREE / relative_path
    assert path.is_file(), f"{PLUGIN_ROOT}/{relative_path} is missing from the committed tree"
    actual = path.read_bytes()
    assert actual == expected, (
        f"{PLUGIN_ROOT}/{relative_path} has drifted from the packaged resources "
        f"(committed {len(actual)} bytes, rendered {len(expected)} bytes). "
        "Regenerate the tree rather than editing it by hand."
    )


def test_the_committed_tree_has_no_unmanaged_extra_files() -> None:
    expected = set(_rendered()) | {_MARKER_NAME}
    present = {
        str(path.relative_to(_COMMITTED_TREE))
        for path in _COMMITTED_TREE.rglob("*")
        if path.is_file()
    }
    assert present - expected == set(), f"unmanaged files under {PLUGIN_ROOT}: {present - expected}"
    assert expected - present == set(), f"missing files under {PLUGIN_ROOT}: {expected - present}"


def test_the_install_marker_records_the_committed_bytes() -> None:
    """A stale marker is how the drift stayed self-consistent and therefore invisible."""

    parsed = strict_json_parse((_COMMITTED_TREE / _MARKER_NAME).read_bytes())
    assert isinstance(parsed, Mapping), "install marker is not an object"
    marker = cast(Mapping[str, JsonValue], parsed)
    managed_files = marker["managed_files"]
    assert isinstance(managed_files, list), "install marker managed_files is not a list"
    entries = [cast(Mapping[str, JsonValue], entry) for entry in managed_files]
    recorded = {cast(str, entry["relative_path"]): entry for entry in entries}
    rendered = _rendered()
    assert set(recorded) == set(rendered), "marker managed_files disagrees with the rendered tree"
    for relative_path, data in sorted(rendered.items()):
        entry = recorded[relative_path]
        assert entry["size"] == len(data), f"marker size is stale for {relative_path}"
        expected_digest = f"sha256:{hashlib.sha256(data).hexdigest()}"
        assert entry["sha256"] == expected_digest, f"marker digest is stale for {relative_path}"

    marker_body = dict(marker)
    recorded_marker_digest = marker_body.pop("marker_digest")
    assert recorded_marker_digest == canonical_digest(marker_body), "marker digest is stale"


def test_the_committed_guidance_matches_the_repository_guidance() -> None:
    """The specific regression: root ``guidance/`` is the single owner of these four files."""

    references = {
        path.name: path.read_bytes()
        for path in sorted((_COMMITTED_TREE / _REFERENCES_PREFIX).iterdir())
        if path.is_file()
    }
    assert references, "the committed plugin tree ships no guidance references"
    for name, data in sorted(references.items()):
        source = _GUIDANCE_DIR / name
        assert source.is_file(), f"committed reference has no owner under guidance/: {name}"
        assert data == source.read_bytes(), (
            f"guidance/{name} and the committed plugin copy have diverged; "
            "guidance/ is the single owner and the copy must be regenerated"
        )


def test_a_real_install_reproduces_the_committed_tree(tmp_path: Path) -> None:
    """Strongest form: what ``install_plugin`` writes today is what is checked in."""

    install_plugin(
        IntegrationTarget(scope=IntegrationScope.TRUSTED_PROJECT, project_root=str(tmp_path)),
        replace_modified=True,
        # Codex has no tested capability set yet (E-002); installing anyway is exactly what the
        # observation setup path does, and is what produced the committed tree.
        allow_untested=True,
    )
    installed_root = tmp_path / PLUGIN_ROOT
    installed = {
        str(path.relative_to(installed_root)): path.read_bytes()
        for path in installed_root.rglob("*")
        if path.is_file()
    }
    committed = {
        str(path.relative_to(_COMMITTED_TREE)): path.read_bytes()
        for path in _COMMITTED_TREE.rglob("*")
        if path.is_file()
    }
    assert installed == committed, (
        f"{PLUGIN_ROOT} is not what a real install produces; regenerate it"
    )
