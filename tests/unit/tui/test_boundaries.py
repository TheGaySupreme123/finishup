"""The import boundaries that make the terminal UI reviewable as presentation.

ADR-017 claims three structural properties. Each is only worth claiming if it is
enforced, and each shows up as an import, so each is checked here rather than
left to review discipline.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Final

import pytest

_TUI: Final = Path(__file__).resolve().parents[3] / "src" / "finishup" / "tui"

# Modules that may legitimately reach into the rest of FinishUP.
_BRIDGES: Final = frozenset({"runtime.py", "app.py"})

_INTERNAL_PREFIXES: Final = (
    "finishup.application",
    "finishup.service",
    "finishup.adapters",
    "finishup.kernel",
    "finishup.ports",
    "finishup.protocol",
    "finishup.config",
    "finishup.domain",
)


def _resolved_import_from(node: ast.ImportFrom, package: tuple[str, ...]) -> set[str]:
    if node.level == 0:
        return {node.module} if node.module else set()
    ancestor_count = node.level - 1
    if ancestor_count > len(package):
        return set()
    base = package[: len(package) - ancestor_count]
    if node.module:
        return {".".join((*base, *node.module.split(".")))}
    return {".".join((*base, alias.name)) for alias in node.names}


def _imported_modules(path: Path) -> set[str]:
    """Every module name this file imports, including inside functions."""

    tree = ast.parse(path.read_text(encoding="utf-8"))
    package = path.relative_to(_TUI.parents[1]).with_suffix("").parts[:-1]
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            names.update(_resolved_import_from(node, package))
    return names


def _code_strings(path: Path) -> str:
    """Every string literal in the file that is not a docstring."""

    tree = ast.parse(path.read_text(encoding="utf-8"))
    docstrings = {
        ast.get_docstring(node, clean=False)
        for node in ast.walk(tree)
        if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef)
    }
    literals = [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    ]
    return "\n".join(value for value in literals if value not in docstrings)


def _tui_sources() -> list[Path]:
    return sorted(_TUI.rglob("*.py"))


def test_the_source_tree_under_test_is_actually_present() -> None:
    modules = {path.name for path in _tui_sources()}
    assert {"runtime.py", "render.py", "app.py", "models.py"} <= modules


def test_relative_imports_resolve_to_their_full_module_names() -> None:
    source = _TUI / "widgets" / "_boundary_relative_import_probe.py"
    tree = ast.parse("from ...application import service\nfrom . import style\n")
    package = source.relative_to(_TUI.parents[1]).with_suffix("").parts[:-1]
    resolved: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            resolved.update(_resolved_import_from(node, package))
    assert resolved == {"finishup.application", "finishup.tui.widgets.style"}


def test_rendering_stays_pure_text_with_no_rendering_framework() -> None:
    """``render.py`` is snapshot-testable only because it imports no UI toolkit."""

    for module in ("render.py", "text.py", "symbols.py", "models.py", "commands.py", "events.py"):
        imported = _imported_modules(_TUI / module)
        offenders = [name for name in imported if name.split(".")[0] in {"textual", "rich"}]
        assert offenders == [], f"{module} imports {offenders}"


def test_widgets_hold_no_security_relevant_logic() -> None:
    """A widget may not reach an application service, a port, or the vault."""

    for path in sorted((_TUI / "widgets").rglob("*.py")):
        imported = _imported_modules(path)
        offenders = [name for name in imported if name.startswith(_INTERNAL_PREFIXES)]
        assert offenders == [], f"{path.name} imports {offenders}"


def test_only_the_declared_bridges_reach_the_application_services() -> None:
    """Anything else touching a service would be a second authority, not a view."""

    for path in _tui_sources():
        if path.name in _BRIDGES:
            continue
        imported = _imported_modules(path)
        offenders = [name for name in imported if name.startswith(_INTERNAL_PREFIXES)]
        assert offenders == [], f"{path.relative_to(_TUI)} imports {offenders}"


def test_no_module_in_the_interface_reads_a_secret_directly() -> None:
    """Secret entry belongs to the confidential ceremony, never to this package."""

    forbidden = ("getpass", "termios", "tty")
    for path in _tui_sources():
        imported = _imported_modules(path)
        offenders = [name for name in imported if name.split(".")[0] in forbidden]
        assert offenders == [], f"{path.relative_to(_TUI)} imports {offenders}"
        # Prose may describe the ceremony's terminal; code may not name it.
        assert "/dev/tty" not in _code_strings(path), path.relative_to(_TUI)


@pytest.mark.parametrize("module", ["render.py", "models.py", "commands.py", "text.py"])
def test_the_pure_modules_import_nothing_from_the_widget_tree(module: str) -> None:
    imported = _imported_modules(_TUI / module)
    assert not any(name.startswith("finishup.tui.widgets") for name in imported)
