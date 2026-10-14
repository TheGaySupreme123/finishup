"""Closed contract for the connection-free isolation proof (issues #518, #567, #571).

``finishup service isolation --json`` emits ``yoetz.isolation-report/1``. It names two kinds of
digest apart:

* **Path-identity digests** (``path_identity.*_path_digest``) bind the canonical resolved path a
  root or file resolves to. They prove *which* target a runtime would use, never what bytes that
  target holds; a path-stable edit leaves them unchanged.
* **Byte-content digests** (``ContentObservation.content_digest``) bind the SHA-256 of one file's
  bytes at one observation time. They carry only the digest, size, existence, and time — never
  the content itself — and are produced only on explicit request.

The untagged 0.2 output (an ``identity`` block whose ``config_digest`` was a path-identity digest)
is not a schema version; consumers detect it by the absent ``schema`` key.
"""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "CONTENT_OBSERVATION_BYTE_LIMIT",
    "ISOLATION_REPORT_SCHEMA",
    "AbsentContentObservation",
    "ContentObservation",
    "ContentPresence",
    "IsolationPathIdentity",
    "IsolationReportContract",
    "PresentContentObservation",
]

ISOLATION_REPORT_SCHEMA: Literal["yoetz.isolation-report/1"] = "yoetz.isolation-report/1"
# Upper bound on bytes one content observation reads; a larger file is reported ``oversized``.
CONTENT_OBSERVATION_BYTE_LIMIT = 16_777_216

type Digest = Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
type ObservedAt = Annotated[
    str, Field(pattern=r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$")
]
type ContentPresence = Literal[
    "present", "absent", "not_regular", "oversized", "unreadable", "unstable"
]


class IsolationPathIdentity(BaseModel):
    """Canonical path-identity digests; none of them binds file bytes."""

    model_config = ConfigDict(extra="forbid", strict=True)

    state_path_digest: Digest
    endpoint_path_digest: Digest
    storage_path_digest: Digest
    config_path_digest: Digest
    executable_path_digest: Digest


class PresentContentObservation(BaseModel):
    """A regular file whose bytes were read completely and stably within the bound."""

    model_config = ConfigDict(extra="forbid", strict=True)

    path_digest: Digest
    presence: Literal["present"]
    content_digest: Digest
    size_bytes: int = Field(ge=0, le=CONTENT_OBSERVATION_BYTE_LIMIT)
    observed_at: ObservedAt


class AbsentContentObservation(BaseModel):
    """No byte digest: the file is absent, not regular, too large, unreadable, or kept changing."""

    model_config = ConfigDict(extra="forbid", strict=True)

    path_digest: Digest
    presence: Literal["absent", "not_regular", "oversized", "unreadable", "unstable"]
    content_digest: None
    size_bytes: None
    observed_at: ObservedAt


type ContentObservation = PresentContentObservation | AbsentContentObservation


class IsolationReportContract(BaseModel):
    """``yoetz.isolation-report/1``: path identity plus an optional config byte-content lane."""

    model_config = ConfigDict(extra="forbid", strict=True)

    schema_tag: Literal["yoetz.isolation-report/1"] = Field(alias="schema")
    mode: Literal["isolated", "ambient"]
    binding: Literal["ambient", "environment", "runtime_pin", "environment_and_pin"]
    lifecycle: Literal["permanent", "persistent", "disposable", "unlabeled"]
    path_identity: IsolationPathIdentity
    config_content: ContentObservation | None
