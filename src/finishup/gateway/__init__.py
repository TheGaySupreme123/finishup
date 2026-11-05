"""``finishup service gateway``: the server side of the HTTPS binding v1 (ADR-051, approach A).

A same-user process on the server host. It authenticates an API key, applies the key's scope as
a method allow-list, refuses ``Origin`` headers and hellos that name a path, and maps each REST
session onto one ordinary control connection to the local daemon, so the daemon itself never
opens a network socket (ADR-008 invariant 6 as amended). It holds no vault, storage or policy
authority: it may import SHARED modules and ``finishup.service.client`` only (the cut line in
``tests/unit/architecture``). Importing this package is inert.
"""

from __future__ import annotations

__all__: tuple[str, ...] = ()
