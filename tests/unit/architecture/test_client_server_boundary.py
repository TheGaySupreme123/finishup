"""The client/server cut line holds: no new import crosses it, and the ledger only shrinks.

Every module under ``src/finishup`` has one side in ``boundary_map``. This walks every module's
AST — module-level imports, imports inside functions and methods, ``TYPE_CHECKING`` blocks, and
constant-string ``importlib.import_module``/``__import__`` calls — and compares each crossing with
``client_server_ledger``. An unlisted crossing fails (it is new), and a ledger entry that no
longer occurs fails too (the ledger must shrink with the code). No package moves: the contract is
this test (ADR-051 slice 1, design section 2).
"""

from __future__ import annotations

import ast
from collections import Counter
from collections.abc import Iterator
from pathlib import Path
from typing import Final

import pytest
from tests.unit.architecture.boundary_map import MODULE_SIDES, allowed, side_of
from tests.unit.architecture.client_server_ledger import DISPOSITIONS, LEDGER, Crossing

_SRC: Final = Path(__file__).resolve().parents[3] / "src" / "finishup"
_DYNAMIC_IMPORTERS: Final = frozenset({"import_module", "__import__"})

type CrossingKey = tuple[str, str, str]


def source_modules(root: Path = _SRC) -> dict[str, Path]:
    """Map every dotted module name under ``root`` to its file (packages by ``__init__``)."""

    modules: dict[str, Path] = {}
    for path in sorted(root.rglob("*.py")):
        parts = path.relative_to(root.parent).with_suffix("").parts
        if parts[-1] == "__init__":
            parts = parts[:-1]
        modules[".".join(parts)] = path
    return modules


def _resolve(name: str, modules: dict[str, Path]) -> str | None:
    """The longest existing module a dotted import name refers to."""

    parts = name.split(".")
    for length in range(len(parts), 0, -1):
        candidate = ".".join(parts[:length])
        if candidate in modules:
            return candidate
    return None


class _ImportCollector(ast.NodeVisitor):
    """Collect ``(imported module, enclosing scope)`` for each import statement in one module."""

    def __init__(self, package: tuple[str, ...], modules: dict[str, Path]) -> None:
        self._package = package
        self._modules = modules
        self._scope: list[str] = []
        self.found: list[tuple[str, str]] = []

    def _record(self, names: list[str]) -> None:
        scope = ".".join(self._scope) or "<module>"
        targets: list[str] = []
        for name in names:
            if name != "finishup" and not name.startswith("finishup."):
                continue
            resolved = _resolve(name, self._modules)
            if resolved is not None and resolved not in targets:
                targets.append(resolved)
        self.found.extend((target, scope) for target in targets)

    def _enter(self, node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef) -> None:
        self._scope.append(node.name)
        self.generic_visit(node)
        self._scope.pop()

    visit_FunctionDef = _enter
    visit_AsyncFunctionDef = _enter
    visit_ClassDef = _enter

    def visit_Import(self, node: ast.Import) -> None:
        self._record([alias.name for alias in node.names])

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.level == 0:
            base = node.module or ""
        else:
            ancestors = self._package[: len(self._package) - (node.level - 1)]
            base = ".".join((*ancestors, *(node.module.split(".") if node.module else ())))
        # ``from finishup.cli import app`` names a submodule; ``from finishup.cli.app import x``
        # names an attribute of the module.
        self._record(
            [
                f"{base}.{alias.name}" if f"{base}.{alias.name}" in self._modules else base
                for alias in node.names
            ]
        )

    def visit_Call(self, node: ast.Call) -> None:
        function = node.func
        name = (
            function.id
            if isinstance(function, ast.Name)
            else function.attr
            if isinstance(function, ast.Attribute)
            else None
        )
        if (
            name in _DYNAMIC_IMPORTERS
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            self._record([node.args[0].value])
        self.generic_visit(node)


def module_imports(module: str, path: Path, modules: dict[str, Path]) -> list[tuple[str, str]]:
    """Every ``(imported finishup module, scope)`` one import statement in ``path`` makes."""

    is_package = path.name == "__init__.py"
    parts = tuple(module.split("."))
    collector = _ImportCollector(parts if is_package else parts[:-1], modules)
    collector.visit(ast.parse(path.read_text(encoding="utf-8")))
    return collector.found


def measured_crossings(root: Path = _SRC) -> Counter[CrossingKey]:
    """Count import statements per ``(importer, imported, scope)`` that cross the cut line."""

    modules = source_modules(root)
    crossings: Counter[CrossingKey] = Counter()
    for module, path in modules.items():
        for imported, scope in module_imports(module, path, modules):
            if not allowed(module, imported):
                crossings[(module, imported, scope)] += 1
    return crossings


def _ledger_counts() -> Counter[CrossingKey]:
    return Counter({entry.key: entry.statements for entry in LEDGER})


def _describe(key: CrossingKey) -> str:
    importer, imported, scope = key
    return f"{importer} -> {imported} in {scope} ({side_of(importer)} -> {side_of(imported)})"


def _all_entries() -> Iterator[Crossing]:
    yield from LEDGER


def test_the_source_tree_under_test_is_present() -> None:
    modules = source_modules()
    assert {"finishup.cli.app", "finishup.service.daemon", "finishup.client"} <= set(modules)


def test_every_module_has_exactly_one_side() -> None:
    unmapped: list[str] = []
    for module in source_modules():
        try:
            side_of(module)
        except KeyError:
            unmapped.append(module)
    assert unmapped == [], f"classify these modules in boundary_map.py: {unmapped}"


def test_map_keys_are_real_modules_or_reserved_packages() -> None:
    """A stale map key would silently classify nothing; reserved names are listed here.

    ``finishup.resources`` holds packaged data only; the gateway package is reserved for the
    approaches that add one.
    """

    modules = set(source_modules())
    reserved = {"finishup.resources", "finishup.gateway"}
    stale = sorted(key for key in MODULE_SIDES if key not in modules and key not in reserved)
    assert stale == []


def test_no_new_crossing_and_no_stale_ledger_entry() -> None:
    measured = measured_crossings()
    ledger = _ledger_counts()
    new = sorted(key for key in measured if measured[key] > ledger.get(key, 0))
    stale = sorted(key for key in ledger if measured.get(key, 0) < ledger[key])
    assert not new, "new client/server crossings:\n" + "\n".join(
        f"  {_describe(key)}: {measured[key]} statement(s), ledger {ledger.get(key, 0)}"
        for key in new
    )
    assert not stale, "ledger entries that no longer occur; shrink the ledger:\n" + "\n".join(
        f"  {_describe(key)}: ledger {ledger[key]}, measured {measured.get(key, 0)}"
        for key in stale
    )


def test_ledger_entries_are_unique_real_crossings_with_closed_dispositions() -> None:
    keys = [entry.key for entry in _all_entries()]
    assert len(keys) == len(set(keys))
    for entry in _all_entries():
        assert entry.disposition in DISPOSITIONS, entry
        assert entry.statements >= 1, entry
        assert not allowed(entry.importer, entry.imported), entry
        # Only a server-host-only crossing names the commands that reach it.
        assert bool(entry.commands) == (entry.disposition == "server_host_only"), entry


def test_the_new_client_package_borrows_no_server_internals() -> None:
    """New client code lives in ``finishup.client``; it may never borrow server internals.

    Its one crossing is ``client_outbox``: the drain that delivers the client's own captured rows
    opens the outbox module the service's observation store shares. That disposition names that
    one module and is open to no other importer.
    """

    client_entries = [
        entry for entry in _all_entries() if entry.importer.startswith("finishup.client")
    ]
    assert {entry.disposition for entry in client_entries} <= {"client_outbox"}
    outbox_entries = [entry for entry in _all_entries() if entry.disposition == "client_outbox"]
    assert outbox_entries == client_entries
    assert {entry.imported for entry in outbox_entries} == {
        "finishup.adapters.integrations.observation_local"
    }


def test_the_workspace_readers_import_only_workspace_and_shared_modules() -> None:
    """A workspace reader runs on whichever host holds the workspace (the client's agent for a
    remote server), so none may reach storage, the vault, providers, the service or a surface;
    no ledger entry may excuse one."""

    workspace = [module for module in source_modules() if side_of(module) == "WORKSPACE"]
    assert "finishup.adapters.git_change_capture" in workspace
    assert "finishup.application.observation_check_policy" in workspace
    assert not [entry for entry in _all_entries() if side_of(entry.importer) == "WORKSPACE"]


def test_relative_and_dynamic_imports_resolve(tmp_path: Path) -> None:
    root = tmp_path / "finishup"
    (root / "cli").mkdir(parents=True)
    (root / "service").mkdir()
    for name in ("__init__.py", "cli/__init__.py", "service/__init__.py", "service/vault.py"):
        (root / name).write_text("", encoding="utf-8")
    (root / "cli" / "probe.py").write_text(
        "from ..service import vault\n"
        "def later():\n"
        "    import importlib\n"
        "    importlib.import_module('finishup.service.vault')\n"
        "    from finishup.service.vault import thing\n",
        encoding="utf-8",
    )
    modules = source_modules(root)
    found = module_imports("finishup.cli.probe", root / "cli" / "probe.py", modules)
    assert found == [
        ("finishup.service.vault", "<module>"),
        ("finishup.service.vault", "later"),
        ("finishup.service.vault", "later"),
    ]


@pytest.mark.parametrize(
    ("importer", "imported", "expected"),
    [
        ("finishup.cli.app", "finishup.protocol.errors", True),
        ("finishup.cli.app", "finishup.service.daemon", False),
        ("finishup.cli.app", "finishup.service.client", True),
        ("finishup.service.daemon", "finishup.cli.observe_hooks", False),
        ("finishup.protocol.errors", "finishup.kernel.claims", False),
        ("finishup.kernel.claims", "finishup.kernel.fact_lineage", True),
        ("finishup.gateway.app", "finishup.service.client", True),
        ("finishup.gateway.app", "finishup.service.daemon", False),
        ("finishup.gateway.app", "finishup.cli.app", False),
        ("finishup.client.targets", "finishup.config.paths", True),
        ("finishup.client.targets", "finishup.adapters.keys.owner_file_store", True),
        ("finishup.client.targets", "finishup.adapters.keys.encrypted_vault", False),
        ("finishup.client.workspace_agent", "finishup.adapters.git_change_capture", True),
        ("finishup.service.workspace_routing", "finishup.adapters.task_input_read", True),
        ("finishup.adapters.git_change_capture", "finishup.adapters.workspace_root", True),
        ("finishup.adapters.git_change_capture", "finishup.adapters.repository_identity", False),
        ("finishup.adapters.approved_checks", "finishup.service.daemon", False),
        ("finishup.application.observation_check_policy", "finishup.cli.app", False),
        ("finishup.protocol.errors", "finishup.adapters.git_version", False),
        ("finishup.gateway.app", "finishup.adapters.workspace_inspect", False),
    ],
)
def test_the_side_rules(importer: str, imported: str, expected: bool) -> None:
    assert allowed(importer, imported) is expected
