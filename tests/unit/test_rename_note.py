"""Every user-facing surface acknowledges the rename with the same sentence."""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

import pytest
from typer.testing import CliRunner

from finishup.legacy_names import RENAME_NOTE

_ROOT = Path(__file__).resolve().parents[2]


def test_the_rename_sentence_is_fixed() -> None:
    assert RENAME_NOTE == "FinishUP was previously called Yoetz."


@pytest.mark.parametrize(
    "relative",
    [
        "README.md",
        "CHANGELOG.md",
        "SECURITY.md",
        "CONTRIBUTING.md",
        "docs/releases/v0.3.0.md",
        "docs/usage/README.md",
        "docs/usage/install-and-first-run.md",
        "docs/usage/upgrading.md",
    ],
)
def test_documents_carry_the_same_sentence(relative: str) -> None:
    assert RENAME_NOTE in (_ROOT / relative).read_text(encoding="utf-8")


def test_package_descriptions_carry_the_same_sentence() -> None:
    project = tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert project["description"].endswith(RENAME_NOTE)
    package = json.loads((_ROOT / "support/npm-launcher/package.json").read_text(encoding="utf-8"))
    assert package["description"].endswith(RENAME_NOTE)


def test_cli_help_carries_the_same_sentence() -> None:
    from finishup.cli.app import app

    result = CliRunner().invoke(app, ["--help"], env={"COLUMNS": "400"})

    assert result.exit_code == 0
    assert RENAME_NOTE in result.output


# PyPI renders README.md as the package's long description and resolves nothing relative to the
# repository, so a relative image is broken there. The README therefore names the tracked logo by
# its raw URL on the default branch of the renamed repository (issue #1056); moving the file breaks
# every published PyPI page, which this test refuses.
_LOGO = "docs/assets/finishup-logo.png"
_LOGO_URL = f"https://raw.githubusercontent.com/TheGaySupreme123/finishup/main/{_LOGO}"


def test_readme_logo_names_the_tracked_asset_by_absolute_url() -> None:
    readme = (_ROOT / "README.md").read_text(encoding="utf-8")

    assert f'<img src="{_LOGO_URL}"' in readme
    assert (_ROOT / _LOGO).is_file()
    assert "https://finishup.dev" in readme


def test_readme_images_are_absolute_for_the_pypi_description() -> None:
    readme = (_ROOT / "README.md").read_text(encoding="utf-8")
    sources = re.findall(r'<img\s[^>]*?src="([^"]*)"', readme)
    sources += re.findall(r"!\[[^\]]*\]\(([^)\s]+)", readme)

    assert sources
    assert [source for source in sources if not source.startswith("https://")] == []
