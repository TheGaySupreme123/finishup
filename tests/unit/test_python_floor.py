"""Source stays runnable on the oldest Python that ``requires-python`` admits (issue #1119).

CI runs the suites on the supported minors, but a developer on the newest one would otherwise
only find a 3.14-only construct after pushing. These checks run on any interpreter.
"""

from __future__ import annotations

import ast
import re
import subprocess
import tomllib
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]


def _floor() -> tuple[int, int]:
    project = tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    match = re.search(r">=\s*3\.(\d+)", project["requires-python"])
    assert match is not None, project["requires-python"]
    return (3, int(match.group(1)))


def _tracked_python_files() -> list[Path]:
    listed = subprocess.run(
        ["git", "ls-files", "-z", "--", "*.py"],
        cwd=_ROOT,
        check=True,
        capture_output=True,
    ).stdout.split(b"\0")
    return [_ROOT / name.decode() for name in listed if name]


def _is_slotted(node: ast.ClassDef) -> bool:
    return any(
        isinstance(decorator, ast.Call)
        and any(
            keyword.arg == "slots"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is True
            for keyword in decorator.keywords
        )
        for decorator in node.decorator_list
    )


def test_floor_matches_supported_classifiers() -> None:
    project = tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    minors = {
        int(found.group(1))
        for classifier in project["classifiers"]
        if (found := re.fullmatch(r"Programming Language :: Python :: 3\.(\d+)", classifier))
    }
    assert min(minors) == _floor()[1]


def test_every_tracked_module_parses_with_the_floor_grammar() -> None:
    floor = _floor()
    failures: list[str] = []
    for path in _tracked_python_files():
        try:
            ast.parse(path.read_bytes(), filename=str(path), feature_version=floor)
        except SyntaxError as error:
            failures.append(f"{path.relative_to(_ROOT)}:{error.lineno}: {error.msg}")
    assert failures == []


def _is_frozen(node: ast.ClassDef) -> bool:
    return any(
        isinstance(decorator, ast.Call)
        and any(
            keyword.arg == "frozen"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is True
            for keyword in decorator.keywords
        )
        for decorator in node.decorator_list
    )


def _base_name(base: ast.expr) -> str:
    if isinstance(base, ast.Name):
        return base.id
    return base.attr if isinstance(base, ast.Attribute) else ""


def test_frozen_slotted_dataclasses_have_no_plain_subclass() -> None:
    # Before Python 3.14, ``slots=True`` rebuilds the class while the generated frozen
    # ``__setattr__`` keeps a ``super()`` bound to the discarded original. A plain subclass whose
    # attributes are assigned (``__traceback__`` when an error crosses a ``@contextmanager``)
    # then raises ``TypeError`` and masks the real error.
    failures: list[str] = []
    for path in _tracked_python_files():
        tree = ast.parse(path.read_bytes(), filename=str(path))
        classes = [node for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]
        frozen_slotted = {node.name for node in classes if _is_slotted(node) and _is_frozen(node)}
        for node in classes:
            if node.decorator_list:
                continue
            for base in node.bases:
                if _base_name(base) in frozen_slotted:
                    failures.append(f"{path.relative_to(_ROOT)}:{node.lineno} {node.name}")
    assert failures == []


def test_slotted_dataclasses_name_their_class_in_super() -> None:
    # Before Python 3.14, ``slots=True`` rebuilds the class, so a zero-argument ``super()``
    # inside it binds the discarded original and raises ``TypeError`` at call time.
    failures: list[str] = []
    for path in _tracked_python_files():
        tree = ast.parse(path.read_bytes(), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef) or not _is_slotted(node):
                continue
            for call in ast.walk(node):
                if (
                    isinstance(call, ast.Call)
                    and isinstance(call.func, ast.Name)
                    and call.func.id == "super"
                    and not call.args
                ):
                    failures.append(f"{path.relative_to(_ROOT)}:{call.lineno} {node.name}")
    assert failures == []
