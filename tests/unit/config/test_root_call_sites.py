"""Every root-resolution call site outside ``config/paths.py`` keeps its audited meaning.

ADR-051 adds the server selection as the lowest-precedence root source. ``active_root()`` follows
it; ``isolated_root()`` keeps meaning "explicitly isolated" (the variable or the runtime pin).
Host registrations, launch lines, the Codex RECORD proof, and the package-upgrade guard must stay
explicit: a selection stamped into a Cursor or Codex registration would freeze that host onto one
target and make every ambient registration look drifted, and ``upgrade`` must keep working while a
target is selected. This test locks the audited classification by AST, so a new call site — or a
quiet switch from one function to the other — fails until it is classified here.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Final

_SRC: Final = Path(__file__).resolve().parents[3] / "src" / "finishup"
_RESOLVERS: Final = frozenset({"isolated_root", "active_root", "_expected_isolated_root"})

# (module path relative to src/finishup, enclosing scope, resolver) -> number of calls.
_FOLLOWS_SELECTION: Final = {
    # Forwards the resolved root to the service (or connector) it spawns.
    ("service/client.py", "_service_environment", "active_root"): 1,
    # The instance-binding check: a named local server's marker lives in an isolated root.
    ("service/daemon.py", "_production_composition", "active_root"): 1,
    # ``service isolation`` reports the root this process really uses.
    ("cli/isolation_status.py", "isolation_report", "active_root"): 1,
    # The workspace fingerprint skips FinishUP's own state, wherever it is.
    ("cli/runtime_facts.py", "_owned_roots", "active_root"): 1,
    # Which folders this installation uses (``isolated`` for any non-ambient root).
    ("cli/service_installation.py", "installation_folders", "active_root"): 1,
    # Direct dial (approach B): the selected root's ``target.json`` picks the transport.
    ("client/transports.py", "transport_for_active_root", "active_root"): 1,
}
_STAYS_EXPLICIT: Final = {
    # Registrations and launch lines stamp only an explicit isolation root.
    ("adapters/integrations/cursor_integration.py", "_render_isolation_root", "isolated_root"): 1,
    ("adapters/integrations/codex_mcp.py", "isolated_root_environment", "isolated_root"): 1,
    (
        "adapters/integrations/codex_mcp.py",
        "CodexMcpAdapter._classify_entry",
        "_expected_isolated_root",
    ): 1,  # noqa: E501
    (
        "adapters/integrations/codex_mcp.py",
        "CodexMcpAdapter.status_registration",
        "_expected_isolated_root",
    ): 1,  # noqa: E501
    (
        "adapters/integrations/codex_mcp.py",
        "CodexMcpAdapter.observe_registration",
        "_expected_isolated_root",
    ): 1,  # noqa: E501
    (
        "adapters/integrations/codex_mcp.py",
        "CodexMcpAdapter._preview_for",
        "_expected_isolated_root",
    ): 1,  # noqa: E501
    (
        "adapters/integrations/codex_mcp.py",
        "CodexMcpAdapter.preview_unregistration",
        "_expected_isolated_root",
    ): 1,  # noqa: E501
    (
        "adapters/integrations/codex_mcp.py",
        "CodexMcpAdapter.apply_unregistration",
        "_expected_isolated_root",
    ): 1,  # noqa: E501
    ("cli/cursor_project_mcp.py", "run_cursor_project_mcp_command", "isolated_root"): 1,
    ("cli/host_connection.py", "prepare_selected", "isolated_root"): 1,
    ("cli/host_connection.py", "launch_details", "isolated_root"): 1,
    ("cli/setup_readiness.py", "continuation", "isolated_root"): 1,
    # The Codex RECORD proof binds the executable to its explicit instance.
    ("adapters/integrations/codex_launcher.py", "installed_launcher", "isolated_root"): 1,
    # ``upgrade`` refuses only an explicitly isolated runtime, never a selection.
    ("adapters/package_upgrade.py", "execute_package_upgrade", "isolated_root"): 1,
}
# New client code that reads the active root to describe or guard the selected target.
_CLIENT_TARGETS: Final = {
    ("client/targets.py", "active_target_record", "active_root"): 1,
    # ``finishup server status``/``connect`` with no name act on this process's own root.
    ("cli/server.py", "_resolve", "active_root"): 1,
}


def _measured() -> dict[tuple[str, str, str], int]:
    found: dict[tuple[str, str, str], int] = {}
    for path in sorted(_SRC.rglob("*.py")):
        relative = path.relative_to(_SRC).as_posix()
        if relative == "config/paths.py":
            continue
        scope: list[str] = []

        class _Visitor(ast.NodeVisitor):
            def _enter(self, node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef) -> None:
                scope.append(node.name)
                self.generic_visit(node)
                scope.pop()

            visit_FunctionDef = _enter
            visit_AsyncFunctionDef = _enter
            visit_ClassDef = _enter

            def visit_Call(self, node: ast.Call) -> None:
                function = node.func
                name = (
                    function.id
                    if isinstance(function, ast.Name)
                    else function.attr
                    if isinstance(function, ast.Attribute)
                    else None
                )
                if name in _RESOLVERS:
                    key = (relative, ".".join(scope) or "<module>", name)
                    found[key] = found.get(key, 0) + 1
                self.generic_visit(node)

        _Visitor().visit(ast.parse(path.read_text(encoding="utf-8")))
    return found


def test_every_root_call_site_matches_its_audited_classification() -> None:
    expected = {**_FOLLOWS_SELECTION, **_STAYS_EXPLICIT, **_CLIENT_TARGETS}
    assert _measured() == expected


def test_the_audit_covers_the_design_table() -> None:
    """Design section 5 lists 20 lines: 5 switch to ``active_root()`` and 15 stay explicit. One
    of the 15 (``codex_mcp.py:578``) is the definition of the Codex adapter's
    ``_expected_isolated_root`` helper, which resolves through ``isolated_root_environment``, so
    the explicit side has 14 calls here. The direct-dial transport seam (approach B) adds a sixth
    call that follows the selection."""

    assert len(_FOLLOWS_SELECTION) == 6
    assert len(_STAYS_EXPLICIT) == 14


def test_registration_and_upgrade_sites_never_follow_the_selection() -> None:
    for module, _scope, resolver in _STAYS_EXPLICIT:
        assert resolver != "active_root", module
    registration_modules = {
        "adapters/integrations/cursor_integration.py",
        "adapters/integrations/codex_mcp.py",
        "adapters/integrations/codex_launcher.py",
        "adapters/package_upgrade.py",
        "cli/cursor_project_mcp.py",
        "cli/host_connection.py",
        "cli/setup_readiness.py",
    }
    for module, _scope, resolver in _measured():
        if module in registration_modules:
            assert resolver != "active_root", module
