"""Every user-facing surface acknowledges the rename with the same sentence."""

from __future__ import annotations

import json
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


def test_readme_logo_is_a_tracked_relative_path() -> None:
    readme = (_ROOT / "README.md").read_text(encoding="utf-8")

    assert '<img src="docs/assets/finishup-logo.png"' in readme
    assert (_ROOT / "docs/assets/finishup-logo.png").is_file()
    assert "https://finishup.dev" in readme
