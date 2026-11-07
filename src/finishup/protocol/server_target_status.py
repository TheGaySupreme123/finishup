"""Closed contract for ``finishup server status --json`` (ADR-051).

``server-target-status`` 1.0.0 names which source decided the root this client uses (the
isolation variable, the runtime pin, the owner-only selection, or the everyday ambient install),
the target it resolves to, and what one probe of that target observed. For a remote target it
also carries what that target's server may read outside the claimed project on this computer
(ADR-051 decision 5): the outside-read mode, where the mode came from, and the folders listed for
it, from this client's own record. ``zero_network_selection`` says when this computer forbids
all network use while a remote server is, or may be, selected (ADR-051 decision 8), by generated
id and closed tokens; it is null otherwise. It is an owner display: the target name, its location
(a host, a URL) and the listed folders appear here and in ``server list``, ``server status`` and
``server folders list`` only, never in errors, logs, hook output, or MCP text. The claim salt and
any credential never appear.
"""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "SERVER_TARGET_STATUS_SCHEMA_VERSION",
    "ServerTargetAuthorization",
    "ServerTargetDescription",
    "ServerTargetOutsideReads",
    "ServerTargetProbe",
    "ServerTargetStatusContract",
    "ServerTargetZeroNetworkSelection",
]

SERVER_TARGET_STATUS_SCHEMA_VERSION: Literal["1.0.0"] = "1.0.0"

type Token = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")]
type Timestamp = Annotated[
    str, Field(pattern=r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$")
]
type TargetId = Annotated[str, Field(pattern=r"^t_[0-9a-f]{8}$")]
# A folder an owner listed: an absolute path in the input-root shape (at most 190 characters).
type ListedFolder = Annotated[
    str, Field(min_length=2, max_length=190, pattern=r"^/[^\x00-\x1f\x7f]+$")
]


class ServerTargetAuthorization(BaseModel):
    """The owner's trusted-console authorization of a remote target."""

    model_config = ConfigDict(extra="forbid", strict=True)

    authorized_at: Timestamp
    disclosure_version: int = Field(ge=1)
    current: bool


class ServerTargetOutsideReads(BaseModel):
    """What a remote target's server may read outside the claimed project on this computer.

    ``mode`` ``local``: as a FinishUP service on this computer would read; ``listed``: only beneath
    ``folders``. Every remote kind has the same two modes. ``mode_source`` says where the mode
    came from: the owner (at ``server add`` or with ``server folders mode``); with none recorded,
    an official FinishUP endpoint (``local``) or no choice yet (``not_chosen``, ``listed``); or a
    record that cannot be read (then ``listed`` with no folder).
    """

    model_config = ConfigDict(extra="forbid", strict=True)

    mode: Literal["local", "listed"]
    mode_source: Literal["owner", "official_endpoint", "not_chosen", "unreadable"]
    folders: list[ListedFolder] = Field(max_length=32)


class ServerTargetDescription(BaseModel):
    """The target the deciding source resolves to (``target_id`` null: not a named target)."""

    model_config = ConfigDict(extra="forbid", strict=True)

    target_id: TargetId | None
    name: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9-]{0,15}$")] | None
    kind: Literal["local", "local_port", "ssh", "https"]
    location: Annotated[str, Field(min_length=1, max_length=2048)] | None
    credential: Literal["keyring", "file", "none", "not_applicable"]
    authorization: ServerTargetAuthorization | None
    # Null for a target that is not remote: a local server reads under its own privacy policy.
    outside_reads: ServerTargetOutsideReads | None


class ServerTargetProbe(BaseModel):
    """One probe: closed outcome and reason tokens, the server's release, and timing."""

    model_config = ConfigDict(extra="forbid", strict=True)

    outcome: Literal["ready", "reachable", "not_running", "unavailable", "not_probed"]
    reason: Token | None
    phase: Token | None
    service_version: Annotated[str, Field(min_length=5, max_length=128)] | None
    service_instance_id: (
        Annotated[
            str,
            Field(pattern=r"^svc_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"),
        ]
        | None
    )
    service_state: Token | None
    vault_mode: Token | None
    round_trip_p95_ms: int | None = Field(ge=0)
    samples: int = Field(ge=0)


class ServerTargetZeroNetworkSelection(BaseModel):
    """This computer forbids all network use while the selection names, or may name, a server on
    another machine, a port or the web (ADR-051 decision 8).

    ``zero_network_remote_selected``: ``target_id`` and ``kind`` name the selected server.
    ``zero_network_selection_unreadable``: the selection could not be read; ``detail`` is its
    closed reason and the server is unknown. Generated ids and closed tokens only.
    """

    model_config = ConfigDict(extra="forbid", strict=True)

    reason: Literal["zero_network_remote_selected", "zero_network_selection_unreadable"]
    target_id: TargetId | None
    kind: Literal["local_port", "ssh", "https"] | None
    detail: Token | None


class ServerTargetStatusContract(BaseModel):
    """``server-target-status`` 1.0.0."""

    model_config = ConfigDict(extra="forbid", strict=True)

    schema_version: Literal["1.0.0"]
    source: Literal["ambient", "environment", "runtime_pin", "environment_and_pin", "selection"]
    selection_overridden: bool
    client_version: Annotated[str, Field(min_length=1, max_length=128)]
    target: ServerTargetDescription
    probe: ServerTargetProbe
    # Null unless this computer is in the zero-network state while a remote server is (or may
    # be) selected: the zero-network setting does not stop traffic to it.
    zero_network_selection: ServerTargetZeroNetworkSelection | None
    observed_at: Timestamp
