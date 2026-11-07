"""A claim-bound connection's human renderings name the producing service; local ones are unchanged.

The attribution is the fixed workspace-evidence line plus the service instance id from the
hello-result and a closed transport token. Nothing user-controlled can join it, a malformed
claim-bound connection never drops it silently, and a line the service's own receipt text already
carries is not repeated (ADR-051).
"""

from __future__ import annotations

import asyncio
from collections.abc import Buffer
from types import SimpleNamespace
from typing import cast

import pytest

from finishup.adapters.control.unix_socket import AuthenticatedUnixStream
from finishup.client.attribution import (
    CONNECTION_TRANSPORTS,
    ServiceAttribution,
    attribution_lines,
    connection_attribution,
)
from finishup.domain.receipts import (
    CLIENT_ATTESTED_WORKSPACE_LINE,
    client_attested_receipt_block,
    workspace_provenance_unknown_block,
)
from finishup.domain.workspace_provenance import (
    SESSION_OPENING_FORMAT_UNKNOWN,
    SESSION_OPENING_REDACTED,
    SESSION_OPENING_UNREADABLE,
    WORKSPACE_PROVENANCE_REASONS,
    WorkspaceProvenanceReason,
)
from finishup.ports.control import ControlClientKind, ControlMethod
from finishup.service import client as client_module
from finishup.service.control_protocol import ControlSession

_SERVICE_ID = "svc_00000000-0000-4000-8000-000000000081"
_HANDLE = "client:0123456789abcdef"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def test_the_transport_tokens_are_a_closed_set() -> None:
    assert CONNECTION_TRANSPORTS == ("unix", "connector", "ssh", "https")


def test_an_attribution_is_the_fixed_line_and_the_producing_service() -> None:
    assert ServiceAttribution(_SERVICE_ID, "ssh").lines() == (
        CLIENT_ATTESTED_WORKSPACE_LINE,
        f"This client reached FinishUP service {_SERVICE_ID} (transport: ssh).",
    )


@pytest.mark.parametrize(
    ("service_instance_id", "transport"),
    [
        ("svc_not-an-id", "ssh"),
        ("lab.example.com", "ssh"),
        (_SERVICE_ID, "tcp"),
        (_SERVICE_ID, "ssh://owner@lab.example"),
    ],
)
def test_nothing_but_an_instance_id_and_a_closed_token_is_accepted(
    service_instance_id: str, transport: str
) -> None:
    with pytest.raises(ValueError, match="service_attribution_invalid"):
        ServiceAttribution(service_instance_id, transport)  # pyright: ignore[reportArgumentType]


@pytest.mark.parametrize("binding", ["none", "local_path", None])
def test_a_connection_that_is_not_claim_bound_has_no_attribution(binding: str | None) -> None:
    connection = SimpleNamespace(
        workspace_binding=binding, service_instance_id=_SERVICE_ID, transport="unix"
    )
    assert connection_attribution(connection) is None
    assert connection_attribution(object()) is None
    assert attribution_lines(connection_attribution(connection)) == ()


def test_a_claim_bound_connection_is_attributed() -> None:
    connection = SimpleNamespace(
        workspace_binding="client_claim", service_instance_id=_SERVICE_ID, transport="https"
    )
    assert connection_attribution(connection) == ServiceAttribution(_SERVICE_ID, "https")


@pytest.mark.parametrize(
    "facts",
    [
        {"service_instance_id": _SERVICE_ID},
        {"transport": "ssh"},
        {"service_instance_id": 7, "transport": "ssh"},
        {"service_instance_id": _SERVICE_ID, "transport": "carrier-pigeon"},
    ],
)
def test_a_malformed_claim_bound_connection_never_drops_its_provenance(
    facts: dict[str, object],
) -> None:
    connection = SimpleNamespace(workspace_binding="client_claim", **facts)
    with pytest.raises(ValueError, match="service_attribution_invalid"):
        connection_attribution(connection)


def test_a_line_the_text_already_carries_is_not_repeated() -> None:
    attribution = ServiceAttribution(_SERVICE_ID, "connector")
    shown = "Conclusion: clean\n" + client_attested_receipt_block(_SERVICE_ID, markdown=False)
    assert attribution_lines(attribution, shown=shown) == (
        f"This client reached FinishUP service {_SERVICE_ID} (transport: connector).",
    )
    assert attribution_lines(attribution) == attribution.lines()
    assert attribution_lines(None, shown=shown) == ()


@pytest.mark.parametrize("reason", WORKSPACE_PROVENANCE_REASONS)
@pytest.mark.parametrize("markdown", [False, True])
def test_a_receipt_whose_provenance_is_unknown_names_only_the_producing_service(
    markdown: bool, reason: WorkspaceProvenanceReason
) -> None:
    """The service could not say where the task's evidence was read, whatever the cause and
    whether it can pass or lasts; the client never overrules that with the connection's line saying it was read on this
    machine (ADR-051)."""

    attribution = ServiceAttribution(_SERVICE_ID, "ssh")
    shown = "Conclusion: clean\n\n" + workspace_provenance_unknown_block(
        markdown=markdown, reason=reason
    )
    assert attribution_lines(attribution, shown=shown) == (
        f"This client reached FinishUP service {_SERVICE_ID} (transport: ssh).",
    )


def test_a_receipt_whose_result_says_the_provenance_is_unknown_names_only_the_producer() -> None:
    """Decision D4: a JSON receipt has no section to read; its ``workspace_provenance`` member
    says the provenance is unknown, so the client's own line is left out."""

    attribution = ServiceAttribution(_SERVICE_ID, "ssh")
    assert attribution_lines(attribution, provenance_unknown=True) == (attribution.lines()[1],)
    assert attribution_lines(attribution) == attribution.lines()
    assert attribution_lines(None, provenance_unknown=True) == ()


@pytest.mark.parametrize(
    "shown",
    [
        "",
        "Conclusion: clean",
        client_attested_receipt_block(_SERVICE_ID, markdown=False),
        workspace_provenance_unknown_block(markdown=True, reason=SESSION_OPENING_UNREADABLE),
        workspace_provenance_unknown_block(markdown=True, reason=SESSION_OPENING_REDACTED),
        workspace_provenance_unknown_block(markdown=True, reason=SESSION_OPENING_FORMAT_UNKNOWN),
        # A page can hold part of the provenance-unknown line, cut where a fragment ends.
        workspace_provenance_unknown_block(markdown=False, reason=SESSION_OPENING_UNREADABLE)[:80],
    ],
)
def test_a_page_of_a_paged_receipt_names_only_the_producing_service(shown: str) -> None:
    """The receipt's own "Workspace evidence" section lands on at most one page, so no page can
    tell whether it says the evidence was client-attested or that this is unknown; the client
    states neither on any page, whatever that page holds (ADR-051)."""

    attribution = ServiceAttribution(_SERVICE_ID, "ssh")
    assert attribution_lines(attribution, shown=shown, receipt_page=True) == (
        f"This client reached FinishUP service {_SERVICE_ID} (transport: ssh).",
    )
    assert attribution_lines(None, shown=shown, receipt_page=True) == ()


# --- the connection carries its facts -----------------------------------------------------------


class _Stream:
    def __init__(self) -> None:
        self.peer_identity = object()
        self._closed = asyncio.Event()

    async def receive(self, max_bytes: int) -> bytes:
        del max_bytes
        await self._closed.wait()
        return b""

    async def send_all(self, data: Buffer) -> None:
        del data

    async def aclose(self) -> None:
        self._closed.set()


def _session(stream: _Stream, *, claim_bound: bool) -> ControlSession:
    return ControlSession(
        protocol_version="1.0",
        client_kind=ControlClientKind.CLI,
        service_instance_id=_SERVICE_ID,
        service_generation="1",
        allowed_methods=tuple(sorted(ControlMethod, key=lambda method: method.value.encode())),
        peer_identity=stream.peer_identity,
        connection_nonce="0" * 64,
        workspace_binding="client_claim" if claim_bound else "local_path",
        workspace_handle=_HANDLE if claim_bound else None,
    )


@pytest.mark.anyio
async def test_a_service_client_reaches_unix_by_default_and_names_its_service() -> None:
    stream = _Stream()
    factory = client_module._connected_client  # pyright: ignore[reportPrivateUsage]
    client = factory(
        cast(AuthenticatedUnixStream, stream),
        _session(stream, claim_bound=False),
        ControlClientKind.CLI,
    )
    try:
        assert client.transport == "unix"
        assert client.service_instance_id == _SERVICE_ID
        assert connection_attribution(client) is None
    finally:
        await client.close()


@pytest.mark.anyio
async def test_whoever_builds_a_claim_bound_client_names_its_transport() -> None:
    stream = _Stream()
    factory = client_module._connected_client  # pyright: ignore[reportPrivateUsage]
    client = factory(
        cast(AuthenticatedUnixStream, stream),
        _session(stream, claim_bound=True),
        ControlClientKind.CLI,
        transport="ssh",
    )
    try:
        assert connection_attribution(client) == ServiceAttribution(_SERVICE_ID, "ssh")
    finally:
        await client.close()


@pytest.mark.anyio
async def test_an_unknown_transport_token_is_refused_at_construction() -> None:
    stream = _Stream()
    factory = client_module._connected_client  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(ValueError, match="connection_transport_invalid"):
        factory(
            cast(AuthenticatedUnixStream, stream),
            _session(stream, claim_bound=True),
            ControlClientKind.CLI,
            transport="lab.example",  # pyright: ignore[reportArgumentType]
        )
