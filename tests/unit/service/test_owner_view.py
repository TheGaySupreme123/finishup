"""r3 F1: the owner receipt view is a one-use, expiring, connection-bound service grant."""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace
from typing import Any, cast

import pytest

from yoetz.application.service import ClientProjectionContext, resolve_client_disclosure_sink
from yoetz.domain.privacy import LocalDisclosureSink
from yoetz.ports.control import ControlClientKind, ControlMethod, ProjectionRenderMode
from yoetz.service.confidential_protocol import (
    OWNER_RECEIPT_VIEW_GRANT_SECONDS,
    ClientOpenEnvelope,
    HumanCeremonyKind,
    decode_human_frame,
    encode_human_frame,
)
from yoetz.service.daemon import ServiceDaemon
from yoetz.service.owner_view import (
    OwnerViewGrants,
    owner_receipt_view_target,
    owner_receipt_view_target_digest,
)

_REQUEST = SimpleNamespace(
    task_id="tsk_00000000-0000-4000-8000-0000000000b1",
    session_id="ses_00000000-0000-4000-8000-0000000000b2",
    request_id="req_00000000-0000-4000-8000-0000000000b3",
    format=SimpleNamespace(value="markdown"),
    include="full",
    redaction_profile="full_local",
)


@pytest.mark.parametrize("kind", list(ControlClientKind))
@pytest.mark.parametrize("mode", list(ProjectionRenderMode))
@pytest.mark.parametrize("tty", [False, True])
def test_presentation_facts_never_select_the_owner_view(
    kind: ControlClientKind, mode: ProjectionRenderMode, tty: bool
) -> None:
    """A forged or genuine terminal presentation, from any client kind, is agent context."""

    sink = resolve_client_disclosure_sink(ClientProjectionContext(kind, mode, tty))
    assert sink is LocalDisclosureSink.AGENT_CONTEXT


def test_only_a_service_set_owner_view_on_a_cli_or_ui_call_is_local_human_view() -> None:
    for kind in ControlClientKind:
        context = ClientProjectionContext(
            kind, ProjectionRenderMode.MACHINE_READABLE, False, owner_view=True
        )
        expected = (
            LocalDisclosureSink.LOCAL_HUMAN_VIEW
            if kind in {ControlClientKind.CLI, ControlClientKind.UI}
            else LocalDisclosureSink.AGENT_CONTEXT
        )
        assert resolve_client_disclosure_sink(context) is expected


def test_grants_are_one_use_and_expire() -> None:
    now = [100.0]
    grants = OwnerViewGrants(lambda: now[0])
    assert grants.issue("sha256:" + "1" * 64) == OWNER_RECEIPT_VIEW_GRANT_SECONDS
    assert grants.consume("sha256:" + "2" * 64) is False
    assert grants.consume("sha256:" + "1" * 64) is True
    assert grants.consume("sha256:" + "1" * 64) is False
    grants.issue("sha256:" + "3" * 64)
    now[0] += OWNER_RECEIPT_VIEW_GRANT_SECONDS
    assert grants.consume("sha256:" + "3" * 64) is False


def test_the_target_round_trips_the_human_control_wire() -> None:
    target = owner_receipt_view_target(_REQUEST, "c" * 64)
    frame = encode_human_frame(
        ClientOpenEnvelope("d" * 64, HumanCeremonyKind.OWNER_RECEIPT_VIEW, target)
    )
    decoded = decode_human_frame(frame)
    assert cast(Any, decoded).target == target
    assert "c" * 64 not in frame.decode("latin-1")
    with pytest.raises(ValueError):
        replace(target, format=cast(Any, "pdf"))


def _daemon(grants: OwnerViewGrants) -> Any:
    return SimpleNamespace(_composition=SimpleNamespace(owner_view_grants=grants))


def _call(method: ControlMethod) -> Any:
    return SimpleNamespace(method=method, body=_REQUEST)


def test_the_daemon_consumes_a_grant_only_for_its_exact_request_and_connection() -> None:
    grants = OwnerViewGrants()
    grants.issue(owner_receipt_view_target_digest(owner_receipt_view_target(_REQUEST, "a" * 64)))
    consume = ServiceDaemon._consume_owner_view  # pyright: ignore[reportPrivateUsage]
    other_connection: Any = SimpleNamespace(
        client_kind=ControlClientKind.CLI, connection_nonce="b" * 64
    )
    agent: Any = SimpleNamespace(
        client_kind=ControlClientKind.MCP_BRIDGE, connection_nonce="a" * 64
    )
    owner: Any = SimpleNamespace(client_kind=ControlClientKind.CLI, connection_nonce="a" * 64)
    assert consume(_daemon(grants), other_connection, _call(ControlMethod.RECEIPT)) is False
    assert consume(_daemon(grants), agent, _call(ControlMethod.RECEIPT)) is False
    assert consume(_daemon(grants), owner, _call(ControlMethod.STATUS)) is False
    assert consume(_daemon(grants), owner, _call(ControlMethod.RECEIPT)) is True
    # One use: the same call again is the agent projection.
    assert consume(_daemon(grants), owner, _call(ControlMethod.RECEIPT)) is False
