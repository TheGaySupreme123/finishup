"""The request id the MCP bridge or the CLI binds to an id-less publish body (issue #1084).

ADR-050 decision 2: agent-facing ``publish_work`` bodies (worked examples, guidance templates,
corrective repairs) may omit ``request_id``; the host mints one per call before the service, whose
model still requires it, validates the body. Tests that check such a body against the service
model apply the same step here.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

BOUND_REQUEST_ID = "req_00000000-0000-4000-8000-000000001084"


def bridge_bound(body: Mapping[str, Any]) -> dict[str, Any]:
    """Return ``body`` with a host-minted ``request_id`` when it has none of its own."""

    if "request_id" in body:
        return dict(body)
    return {**body, "request_id": BOUND_REQUEST_ID}
