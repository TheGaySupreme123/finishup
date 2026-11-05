"""The client/server cut line as a module map (ADR-051 slice 1, design section 2).

Every module under ``src/finishup`` carries exactly one side. The longest matching prefix wins, so
a submodule may override its package (``adapters.keys.os_keyring`` is SHARED inside the SERVER
``adapters.keys`` vault package). No package moves: the cut line is this contract plus the AST
test beside it, which fails on any new crossing and on any ledger entry that no longer occurs.

* SHARED modules may import SHARED modules only.
* CLIENT modules may import CLIENT and SHARED modules.
* SERVER modules may import SERVER and SHARED modules.
* GATEWAY modules (a same-user control client on the server host) may import SHARED modules and
  ``finishup.service.client`` only.
* ``finishup.cli.gateway`` — the ``server_host`` commands that run the gateway and manage its
  keys — is the one CLIENT module that may import GATEWAY modules: it launches them.
"""

from __future__ import annotations

from typing import Final, Literal

__all__ = [
    "GATEWAY_LAUNCHER",
    "GATEWAY_SERVICE_CLIENT",
    "MODULE_SIDES",
    "Side",
    "allowed",
    "side_of",
]

type Side = Literal["SHARED", "CLIENT", "SERVER", "GATEWAY"]

MODULE_SIDES: Final[dict[str, Side]] = {
    # The package root marker (exact match only: it is never a prefix fallback, so a new top-level
    # package must be classified here) and its entry point, which hands off to the CLI entry.
    "finishup": "SHARED",
    "finishup.__main__": "CLIENT",
    "finishup.legacy_names": "SHARED",
    "finishup.version": "SHARED",
    # Pure contracts and configuration shared by both sides.
    "finishup.protocol": "SHARED",
    "finishup.ports": "SHARED",
    "finishup.domain": "SHARED",
    "finishup.config": "SHARED",
    "finishup.observability": "SHARED",
    "finishup.resources": "SHARED",
    # Agent- and user-facing surfaces.
    "finishup.cli": "CLIENT",
    "finishup.mcp": "CLIENT",
    "finishup.tui": "CLIENT",
    "finishup.client": "CLIENT",
    # The service: everything is server-side except the wire codecs and the two clients.
    "finishup.service": "SERVER",
    "finishup.service.control_protocol": "SHARED",
    "finishup.service.confidential_protocol": "SHARED",
    "finishup.service.client": "CLIENT",
    "finishup.service.confidential_client": "CLIENT",
    # Application services are server-side except the client logic that installs, connects, and
    # drains on the client host.
    "finishup.application": "SERVER",
    "finishup.application.harness_mcp": "CLIENT",
    "finishup.application.host_connection": "CLIENT",
    "finishup.application.codex_plugin": "CLIENT",
    "finishup.application.applied_mcp_route": "CLIENT",
    "finishup.application.upgrade": "CLIENT",
    "finishup.application.package_update": "CLIENT",
    "finishup.application.observation_check_policy": "CLIENT",
    "finishup.application.observation_drain": "CLIENT",
    # The kernel is server-side except two pure renderers the client surfaces share.
    "finishup.kernel": "SERVER",
    "finishup.kernel.fact_lineage": "SHARED",
    "finishup.kernel.claim_verification": "SHARED",
    # Adapters: storage, vault, providers, and every read of the workspace for the service are
    # server-side; host integrations and the client's own process facts are client-side.
    "finishup.adapters": "SERVER",
    "finishup.adapters.control": "SHARED",
    "finishup.adapters.control.unix_socket": "SHARED",
    "finishup.adapters.git_rev_parse": "SHARED",
    "finishup.adapters.git_version": "SHARED",
    "finishup.adapters.git_subject_state": "SHARED",
    "finishup.adapters.workspace_root": "SHARED",
    "finishup.adapters.keys.os_keyring": "SHARED",
    "finishup.adapters.keys.owner_file_store": "SHARED",
    "finishup.adapters.integrations": "CLIENT",
    "finishup.adapters.integrations.observation_local": "SERVER",
    "finishup.adapters.workspace_binding": "CLIENT",
    "finishup.adapters.workspace_fingerprint": "CLIENT",
    "finishup.adapters.mcp_stdio": "CLIENT",
    "finishup.adapters.process_lifetime": "CLIENT",
    "finishup.adapters.release_runtime": "CLIENT",
    "finishup.adapters.package_upgrade": "CLIENT",
    # A same-user control client of the daemon on the server host (approach-owned package).
    "finishup.gateway": "GATEWAY",
}

# The one service module a gateway may import besides SHARED modules.
GATEWAY_SERVICE_CLIENT: Final = "finishup.service.client"
# The one client module that may import the gateway: the server-host commands that launch it.
GATEWAY_LAUNCHER: Final = "finishup.cli.gateway"


def side_of(module: str) -> Side:
    """Return the side of ``module`` by longest matching prefix; raise for an unmapped name."""

    if module == "finishup":
        return MODULE_SIDES[module]
    parts = module.split(".")
    for length in range(len(parts), 1, -1):
        side = MODULE_SIDES.get(".".join(parts[:length]))
        if side is not None:
            return side
    raise KeyError(module)


def allowed(importer: str, imported: str) -> bool:
    """Whether ``importer`` may import ``imported`` without a ledger entry."""

    source = side_of(importer)
    target = side_of(imported)
    if target == "SHARED":
        return True
    if source == "SHARED":
        return False
    if source == "GATEWAY":
        return imported == GATEWAY_SERVICE_CLIENT or target == "GATEWAY"
    if target == "GATEWAY":
        return importer == GATEWAY_LAUNCHER
    return source == target
