"""Service-internal application contracts and use-case coordination.

Re-exports resolve lazily (PEP 562). Importing any one submodule used to drag
the whole package surface — publish_work → unit_of_work → ports.ledger →
domain.events → protocol.models — costing ~193 ms on every Codex hook, which
consumes none of these names (#242).
"""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from finishup.application.publish_work import PublishWorkInternalResult
    from finishup.application.receipt import ReceiptInternalResult
    from finishup.application.respond import RespondInternalResult
    from finishup.application.service import (
        Application,
        ClientProjectionContext,
        ControlProjectionBinding,
        ProjectedControlBody,
        ProjectionBindingFacts,
        ProjectionRenderMode,
        ReadyApplicationFactory,
        ServiceReadyContext,
        UnprojectedControlBody,
        VerificationPolicy,
        resolve_client_disclosure_sink,
    )
    from finishup.application.start import StartInternalResult
    from finishup.application.status import StatusInternalResult

__all__ = [
    "Application",
    "ClientProjectionContext",
    "ControlProjectionBinding",
    "ProjectedControlBody",
    "ProjectionBindingFacts",
    "ProjectionRenderMode",
    "PublishWorkInternalResult",
    "ReadyApplicationFactory",
    "ReceiptInternalResult",
    "RespondInternalResult",
    "ServiceReadyContext",
    "StartInternalResult",
    "StatusInternalResult",
    "UnprojectedControlBody",
    "VerificationPolicy",
    "resolve_client_disclosure_sink",
]

_LAZY: Final[dict[str, str]] = {
    "Application": "finishup.application.service",
    "ClientProjectionContext": "finishup.application.service",
    "ControlProjectionBinding": "finishup.application.service",
    "ProjectedControlBody": "finishup.application.service",
    "ProjectionBindingFacts": "finishup.application.service",
    "ProjectionRenderMode": "finishup.application.service",
    "PublishWorkInternalResult": "finishup.application.publish_work",
    "ReadyApplicationFactory": "finishup.application.service",
    "ReceiptInternalResult": "finishup.application.receipt",
    "RespondInternalResult": "finishup.application.respond",
    "ServiceReadyContext": "finishup.application.service",
    "StartInternalResult": "finishup.application.start",
    "StatusInternalResult": "finishup.application.status",
    "UnprojectedControlBody": "finishup.application.service",
    "VerificationPolicy": "finishup.application.service",
    "resolve_client_disclosure_sink": "finishup.application.service",
}


def __getattr__(name: str) -> object:
    module = _LAZY.get(name)
    if module is None:
        raise AttributeError(name)
    value = getattr(importlib.import_module(module), name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted({*globals(), *_LAZY})
