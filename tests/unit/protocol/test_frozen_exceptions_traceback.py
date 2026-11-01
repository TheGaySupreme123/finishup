"""Frozen dataclass errors survive a ``@contextmanager`` (#1119, #1280).

Python 3.14's ``contextlib`` assigns ``__traceback__`` on an exception that leaves a generator
context manager. A frozen dataclass rejects every assignment on its own exact class, so an error
raised under ``host_config_lock`` surfaced as ``FrozenInstanceError`` and then a bare
``internal_error``. Every frozen error class is raised through a thin non-dataclass subclass.
"""

from __future__ import annotations

import ast
import contextlib
import dataclasses
from collections.abc import Generator
from pathlib import Path
from typing import cast

import finishup


def _frozen_error_classes() -> list[tuple[str, str]]:
    root = Path(finishup.__file__).parent
    found: list[tuple[str, str]] = []
    for path in sorted(root.rglob("*.py")):
        if "resources" in path.parts:
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not isinstance(node, ast.ClassDef):
                continue
            frozen = any(
                isinstance(item, ast.Call)
                and getattr(item.func, "id", getattr(item.func, "attr", "")) == "dataclass"
                and any(
                    keyword.arg == "frozen" and getattr(keyword.value, "value", False)
                    for keyword in item.keywords
                )
                for item in node.decorator_list
            )
            bases = [ast.unparse(base) for base in node.bases]
            if frozen and any(
                base in {"Exception", "ValueError", "RuntimeError"} or base.endswith("Error")
                for base in bases
            ):
                module = ".".join(path.relative_to(root.parent).with_suffix("").parts)
                found.append((module, node.name))
    return found


def test_every_frozen_error_dataclass_is_only_a_private_fields_base() -> None:
    offenders = [name for _module, name in _frozen_error_classes() if not name.startswith("_")]
    assert offenders == []


def test_a_raised_frozen_error_keeps_its_type_through_a_context_manager() -> None:
    import importlib

    @contextlib.contextmanager
    def lock() -> Generator[None]:
        yield

    checked = 0
    for module_name, fields_name in _frozen_error_classes():
        module = importlib.import_module(module_name)
        public = [
            value
            for value in vars(module).values()
            if isinstance(value, type)
            and value.__name__ != fields_name
            and getattr(module, fields_name) in value.__mro__[1:2]
        ]
        assert public, fields_name
        error_type = cast(type[BaseException], public[0])
        error = BaseException.__new__(error_type)
        try:
            with lock():
                raise error
        except dataclasses.FrozenInstanceError:  # pragma: no cover - the regression
            raise AssertionError(f"{error_type.__name__} lost its type") from None
        except BaseException as caught:  # noqa: BLE001 - the raised object itself
            assert caught is error
            assert caught.__traceback__ is not None
        checked += 1
    assert checked >= 9
