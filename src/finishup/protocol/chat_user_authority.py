"""Chat-user authority attestation for agent-mediated setup (issue #164)."""

from __future__ import annotations

from typing import Annotated, Final, Literal

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "CHAT_USER_AUTHORITY_CLIENTS",
    "ChatUserAttestationModel",
    "agent_chat_attestation_supported",
]

type Digest = Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
type PendingId = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
type ChatUserClientKind = Literal["codex"]
type ChatInstructionSource = Literal["explicit_current_chat_user"]

# First-party clients whose skill contract may relay an exact current-chat instruction.
# Membership is compatibility only; it is not independent evidence of who instructed the agent.
CHAT_USER_AUTHORITY_CLIENTS: Final[frozenset[str]] = frozenset({"codex"})

_CLOSED_CONFIG = ConfigDict(extra="forbid", frozen=True, strict=True, validate_default=True)


class ChatUserAttestationModel(BaseModel):
    """Exact agent assertion about a current-chat instruction; never a reusable grant.

    FinishUP can bind and consume this assertion, but cannot independently authenticate its chat
    provenance. A compromised or dishonest agent can forge it; the stronger trusted-console path
    remains available.
    """

    model_config = _CLOSED_CONFIG

    schema_: Literal["yoetz.chat-user-attestation/1"] = Field(alias="schema")
    channel: Literal["agent_attested_chat_instruction"]
    client_kind: ChatUserClientKind
    instruction_source: ChatInstructionSource
    pending_id: PendingId
    operation: Annotated[str, Field(min_length=1, max_length=64)]
    danger_digest: Digest
    target_digest: Digest
    warning_acknowledged: bool
    decision: Literal["approve", "deny"]


def agent_chat_attestation_supported(client_kind: str, instruction_source: str) -> bool:
    """Return whether this client/assertion shape is supported, not whether it is authoritative."""

    return (
        type(client_kind) is str
        and client_kind in CHAT_USER_AUTHORITY_CLIENTS
        and instruction_source == "explicit_current_chat_user"
    )
