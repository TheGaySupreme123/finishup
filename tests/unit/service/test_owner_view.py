"""r3 F1: the owner receipt view is a one-use, expiring, connection-bound service grant."""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace
from typing import Any, cast

import pytest

from finishup.application.service import ClientProjectionContext, resolve_client_disclosure_sink
from finishup.domain.privacy import LocalDisclosureSink
from finishup.ports.control import ControlClientKind, ControlMethod, ProjectionRenderMode
from finishup.service.confidential_protocol import (
    OWNER_RECEIPT_VIEW_GRANT_SECONDS,
    ClientOpenEnvelope,
    HumanCeremonyKind,
    decode_human_frame,
    encode_human_frame,
)
from finishup.service.daemon import ServiceDaemon
from finishup.service.owner_view import (
    OwnerViewConnectionRefused,
    OwnerViewGrants,
    control_connection_digest,
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


def test_grants_are_one_use_expire_and_belong_to_one_admission() -> None:
    now = [100.0]
    grants = OwnerViewGrants(lambda: now[0])
    owner = grants.admit("a" * 64)
    other = grants.admit("b" * 64)
    assert owner != other and len(owner) == 64
    connection = control_connection_digest("a" * 64)
    assert grants.issue("sha256:" + "1" * 64, connection) == OWNER_RECEIPT_VIEW_GRANT_SECONDS
    assert grants.consume(other, "sha256:" + "1" * 64) is False
    assert grants.consume(owner, "sha256:" + "2" * 64) is False
    assert grants.consume(owner, "sha256:" + "1" * 64) is True
    assert grants.consume(owner, "sha256:" + "1" * 64) is False
    grants.issue("sha256:" + "3" * 64, connection)
    now[0] += OWNER_RECEIPT_VIEW_GRANT_SECONDS
    assert grants.consume(owner, "sha256:" + "3" * 64) is False


def test_a_duplicate_or_reused_nonce_is_never_admitted() -> None:
    """R3-F1: the hello nonce is client-chosen, so the service refuses any repeat of it."""

    grants = OwnerViewGrants()
    owner = grants.admit("a" * 64)
    with pytest.raises(OwnerViewConnectionRefused):
        grants.admit("a" * 64)
    grants.release(owner)
    with pytest.raises(OwnerViewConnectionRefused):
        grants.admit("a" * 64)


def test_release_revokes_and_a_closed_connection_cannot_be_granted() -> None:
    grants = OwnerViewGrants()
    owner = grants.admit("a" * 64)
    connection = control_connection_digest("a" * 64)
    grants.issue("sha256:" + "1" * 64, connection)
    grants.release(owner)
    assert grants.consume(owner, "sha256:" + "1" * 64) is False
    with pytest.raises(LookupError):
        grants.issue("sha256:" + "1" * 64, connection)
    with pytest.raises(LookupError):
        grants.issue("sha256:" + "1" * 64, control_connection_digest("f" * 64))


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


def test_the_daemon_consumes_a_grant_only_for_its_exact_request_and_admission() -> None:
    grants = OwnerViewGrants()
    owner_admission = grants.admit("a" * 64)
    other_admission = grants.admit("b" * 64)
    grants.issue(
        owner_receipt_view_target_digest(owner_receipt_view_target(_REQUEST, "a" * 64)),
        control_connection_digest("a" * 64),
    )
    consume = ServiceDaemon._consume_owner_view  # pyright: ignore[reportPrivateUsage]
    owner: Any = SimpleNamespace(client_kind=ControlClientKind.CLI, connection_nonce="a" * 64)
    agent: Any = SimpleNamespace(
        client_kind=ControlClientKind.MCP_BRIDGE, connection_nonce="a" * 64
    )
    receipt = _call(ControlMethod.RECEIPT)
    # A session presenting the owner's nonce under another admission gets nothing.
    assert consume(_daemon(grants), owner, receipt, other_admission) is False
    assert consume(_daemon(grants), owner, receipt, None) is False
    assert consume(_daemon(grants), agent, receipt, owner_admission) is False
    assert consume(_daemon(grants), owner, _call(ControlMethod.STATUS), owner_admission) is False
    assert consume(_daemon(grants), owner, receipt, owner_admission) is True
    # One use: the same call again is the agent projection.
    assert consume(_daemon(grants), owner, receipt, owner_admission) is False


def test_closed_connection_memory_stays_bounded_while_an_early_connection_lives(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#1073 review P3: a long-lived first connection must not unbound the refused set."""

    import secrets

    from finishup.service import owner_view

    monkeypatch.setattr(owner_view, "_MAX_SEEN_CONNECTIONS", 100)
    grants = OwnerViewGrants()
    early_nonce = secrets.token_hex(32)
    early = grants.admit(early_nonce)  # an MCP bridge or the TUI holding its connection
    recent: list[str] = []
    for _ in range(500):
        nonce = secrets.token_hex(32)
        grants.release(grants.admit(nonce))
        recent.append(nonce)
    assert len(grants._seen) <= 100  # pyright: ignore[reportPrivateUsage]
    # The early connection is still live, and still cannot be admitted twice.
    with pytest.raises(OwnerViewConnectionRefused):
        grants.admit(early_nonce)
    # A recently closed connection's nonce stays refused.
    with pytest.raises(OwnerViewConnectionRefused):
        grants.admit(recent[-1])
    digest = owner_receipt_view_target_digest(owner_receipt_view_target(_REQUEST, early_nonce))
    grants.issue(digest, control_connection_digest(early_nonce))
    assert grants.consume(early, digest) is True
