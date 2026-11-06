"""Which FinishUP service produced a remote connection's results, said in every human rendering.

A connection to a FinishUP server on another machine binds its workspace by claim
(``workspace_binding == "client_claim"``, ADR-051), and every piece of workspace evidence that
server holds came from this client's workspace agent. The human status and receipt renderings of
such a connection — CLI text, MCP text and the terminal interface — end with the fixed
provenance line, then name the producing service by the instance id its hello-result carried and
by how this client reached it; a receipt whose service text says the provenance is unknown keeps
only the second line. Nothing user-controlled joins either line: no target name, host,
address or path. JSON output stays unattributed. A connection that is not claim-bound renders
nothing here, so local output keeps its exact bytes.

Transport tokens (closed; whoever builds the connection supplies one, ``unix`` by default):

* ``unix`` — the owner-only Unix control endpoint of a service on this machine;
* ``connector`` — a local relay process that carries the connection on to the server;
* ``ssh`` — an SSH channel this client process opened to the server host;
* ``https`` — HTTPS this client process speaks to the server or its network edge.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Literal

from finishup.domain.receipts import (
    CLIENT_ATTESTED_WORKSPACE_LINE,
    WORKSPACE_PROVENANCE_UNKNOWN_LINE,
)
from finishup.protocol.errors import ProtocolValueError
from finishup.protocol.ids import IdKind, validate_id

__all__ = [
    "CONNECTION_TRANSPORTS",
    "ConnectionTransport",
    "ServiceAttribution",
    "attribution_lines",
    "connection_attribution",
]

type ConnectionTransport = Literal["unix", "connector", "ssh", "https"]
CONNECTION_TRANSPORTS: Final[tuple[ConnectionTransport, ...]] = (
    "unix",
    "connector",
    "ssh",
    "https",
)


@dataclass(frozen=True, slots=True)
class ServiceAttribution:
    """The producing service of a claim-bound connection and how this client reached it."""

    service_instance_id: str
    transport: ConnectionTransport

    def __post_init__(self) -> None:
        try:
            validate_id(IdKind.SERVICE_INSTANCE, self.service_instance_id)
        except ProtocolValueError:
            raise ValueError("service_attribution_invalid") from None
        if self.transport not in CONNECTION_TRANSPORTS:
            raise ValueError("service_attribution_invalid")

    def lines(self) -> tuple[str, str]:
        """The fixed provenance line, then the producing service; fixed words and tokens only."""

        return (
            CLIENT_ATTESTED_WORKSPACE_LINE,
            f"This client reached FinishUP service {self.service_instance_id} "
            f"(transport: {self.transport}).",
        )


def connection_attribution(connection: object) -> ServiceAttribution | None:
    """The attribution of ``connection``'s results, or None when it is not claim-bound.

    Reads the connection's ``workspace_binding``, ``service_instance_id`` and ``transport``;
    ``ServiceClient`` carries all three, and any other client offering the same public methods
    must too. A claim-bound connection whose facts are missing or malformed raises
    ``ValueError("service_attribution_invalid")``: provenance is never silently dropped.
    """

    if getattr(connection, "workspace_binding", None) != "client_claim":
        return None
    service_instance_id: object = getattr(connection, "service_instance_id", None)
    transport: object = getattr(connection, "transport", None)
    if type(service_instance_id) is not str or transport not in CONNECTION_TRANSPORTS:
        raise ValueError("service_attribution_invalid")
    return ServiceAttribution(service_instance_id, transport)


def attribution_lines(
    attribution: ServiceAttribution | None, *, shown: str = ""
) -> tuple[str, ...]:
    """The lines a status or receipt rendering ends with; none without an attribution.

    A line that ``shown`` already carries is not repeated: the service's own text and markdown
    receipt of a claim-bound task already ends with the fixed provenance line. When ``shown``
    carries the service's provenance-unknown line instead, the task's own opening record could not
    say where its workspace evidence was read, so the connection's fixed provenance line, which
    would say the opposite, is left out too and only the producing service is named (ADR-051).
    """

    if attribution is None:
        return ()
    unknown = WORKSPACE_PROVENANCE_UNKNOWN_LINE in shown
    return tuple(
        line
        for line in attribution.lines()
        if line not in shown and not (unknown and line == CLIENT_ATTESTED_WORKSPACE_LINE)
    )
