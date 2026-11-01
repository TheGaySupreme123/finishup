"""Persistent local-service package boundary.

Importing this package is deliberately inert.  Concrete service components live in
their owning modules and are loaded only when explicitly requested.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from finishup.ports.control import ServiceState

if TYPE_CHECKING:
    from finishup.service.client import ServiceClient

__all__ = ["ServiceClient", "ServiceState"]


def __getattr__(name: str) -> Any:
    """Lazily expose the client without importing transport adapters at package import."""

    if name == "ServiceClient":
        from finishup.service.client import ServiceClient

        return ServiceClient
    raise AttributeError(name)
