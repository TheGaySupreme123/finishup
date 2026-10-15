"""Bounded read-only service probe, isolated from the host-critical hook process."""

from __future__ import annotations

import json
import sys
from collections.abc import Mapping

from finishup.protocol.canonical import JsonValue


async def probe(request: Mapping[str, JsonValue]) -> bool:
    import anyio

    from finishup import __version__
    from finishup.ports.control import ControlClientKind, WorkspaceLocator
    from finishup.protocol.ids import IdKind, new_id
    from finishup.protocol.models import StatusCompactPageModel, StatusRequest, StatusSuccessModel
    from finishup.service.client import connect_service

    route, workspace = request.get("route"), request.get("workspace")
    if not isinstance(route, list) or len(route) != 3 or not isinstance(workspace, str):
        return False
    client = None
    try:
        with anyio.fail_after(0.65):
            client = await connect_service(
                ControlClientKind.CLI, workspace_locator=WorkspaceLocator(workspace)
            )
            response = await client.status(
                StatusRequest.model_validate(
                    {
                        "protocol_version": "0.1",
                        "schema_version": "1.0.0",
                        "request_id": new_id(IdKind.REQUEST),
                        # Frozen legacy identifier (ADR-048): a recorded actor id existing
                        # ledgers carry.
                        "actor": {"actor_id": "yoetz:startup-gate", "actor_type": "harness"},
                        "client": {
                            # Frozen legacy identifier (ADR-048): the released client-kind
                            # wire value.
                            "kind": "yoetz_cli",
                            "version": __version__,
                            "integration": "local_cli",
                        },
                        "session_id": route[1],
                        "writer_id": route[2],
                        "view": "compact",
                        "limit": "1",
                    }
                ),
                deadline_ms=500,
            )
            result = response.root
            if not isinstance(result, StatusSuccessModel) or not isinstance(
                result.page, StatusCompactPageModel
            ):
                return False
            if (
                [result.task_id, result.session_id, result.writer_id] != route
                or result.rebuild_state != "current"
                or result.projection_lag != "0"
                or len(result.page.items) != 1
            ):
                return False
            item = result.page.items[0]
            return (
                item.current_plan_event_id == request.get("plan_id")
                and item.declared_obligation_count == str(request.get("obligation_count"))
                and item.declared_obligation_count not in {None, "0"}
                and item.open_obligation_count is not None
            )
    finally:
        if client is not None:
            with anyio.move_on_after(0.05, shield=True):
                await client.close()


def main() -> None:
    ready = False
    try:
        raw = sys.stdin.buffer.read(16_385)
        if len(raw) <= 16_384:
            request: JsonValue = json.loads(raw)
            if isinstance(request, dict):
                import anyio

                ready = anyio.run(probe, request)
    except Exception:
        pass
    # No exception text, task prose, identities, or workspace leaves the probe.
    print(json.dumps({"ready": ready}))


if __name__ == "__main__":
    main()
