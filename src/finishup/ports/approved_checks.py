"""Approved-check value types shared by the service and a client workspace agent (ADR-051).

The runner that executes an approved argv stays in ``finishup.adapters.approved_checks``; these
are its pure, validated inputs and results, kept here so the workspace-agent catalog can carry
them over a connection without importing the runner.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Final

from finishup.protocol.canonical import JsonValue, canonical_digest
from finishup.protocol.errors import ProtocolValueError

__all__ = [
    "APPROVED_CHECK_FORMAT",
    "MAX_APPROVED_CHECK_ARGV",
    "MAX_APPROVED_CHECK_ARG_BYTES",
    "MAX_APPROVED_CHECK_OUTPUT_BYTES",
    "ApprovedCheckApproval",
    "ApprovedCheckOutcome",
    "ApprovedCheckResult",
    "ApprovedCheckStatus",
    "approval_commitment",
    "approved_check_result_digest",
]

APPROVED_CHECK_FORMAT: Final = "yoetz.approved-check/1"
MAX_APPROVED_CHECK_OUTPUT_BYTES: Final = 65_536
MAX_APPROVED_CHECK_ARGV: Final = 32
MAX_APPROVED_CHECK_ARG_BYTES: Final = 512
_TOKEN_CHARS: Final = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._/+-="
)


class ApprovedCheckStatus(str, Enum):  # noqa: UP042 - exact wire enum
    PASSED = "passed"
    FAILED = "failed"
    REJECTED = "rejected"
    TIMEOUT = "timeout"
    STALE = "stale"


class ApprovedCheckOutcome(str, Enum):  # noqa: UP042 - exact wire enum
    SUCCESS = "success"
    NONZERO_EXIT = "nonzero_exit"
    NOT_APPROVED = "not_approved"
    UNSAFE_ARGV = "unsafe_argv"
    NETWORK_DENIED = "network_denied"
    SANDBOX_UNAVAILABLE = "sandbox_unavailable"
    OUTPUT_TRUNCATED = "output_truncated"
    TIMEOUT = "timeout"
    EXEC_FAILED = "exec_failed"
    SUBJECT_STATE_MISMATCH = "subject_state_mismatch"


@dataclass(frozen=True, slots=True)
class ApprovedCheckApproval:
    """Commitment-backed approval for one exact argv under a workspace policy."""

    approval_id: str
    argv: tuple[str, ...]
    allow_network: bool
    timeout_seconds: float
    approval_commitment: str

    def __post_init__(self) -> None:
        if (
            type(self.approval_id) is not str
            or not self.approval_id
            or len(self.approval_id) > 128
            or type(self.argv) is not tuple
            or not 1 <= len(self.argv) <= MAX_APPROVED_CHECK_ARGV
            or type(self.allow_network) is not bool
            or type(self.timeout_seconds) is not float
            or not 0.1 <= self.timeout_seconds <= 300.0
            or type(self.approval_commitment) is not str
            or not self.approval_commitment.startswith("sha256:")
        ):
            raise ProtocolValueError("invalid_approved_check")
        for arg in self.argv:
            if (
                type(arg) is not str
                or not arg
                or len(arg.encode("utf-8")) > MAX_APPROVED_CHECK_ARG_BYTES
                or any(ch not in _TOKEN_CHARS and ch not in {":", "@"} for ch in arg)
            ):
                raise ProtocolValueError("invalid_approved_check")
        expected = approval_commitment(
            self.approval_id, self.argv, allow_network=self.allow_network
        )
        if self.approval_commitment != expected:
            raise ProtocolValueError("invalid_approved_check")


@dataclass(frozen=True, slots=True)
class ApprovedCheckResult:
    status: ApprovedCheckStatus
    outcome: ApprovedCheckOutcome
    exit_status: int | None
    output_digest: str | None
    output_bytes: int
    subject_state_digest: str
    approval_commitment: str
    result_digest: str
    duration_ms: int

    def __post_init__(self) -> None:
        if type(self.status) is not ApprovedCheckStatus:
            raise ProtocolValueError("invalid_approved_check")
        if type(self.outcome) is not ApprovedCheckOutcome:
            raise ProtocolValueError("invalid_approved_check")
        if self.exit_status is not None and (
            type(self.exit_status) is not int or not 0 <= self.exit_status <= 255
        ):
            raise ProtocolValueError("invalid_approved_check")
        if self.output_digest is not None and (
            type(self.output_digest) is not str
            or not self.output_digest.startswith("sha256:")
            or len(self.output_digest) != 71
        ):
            raise ProtocolValueError("invalid_approved_check")
        if (
            type(self.output_bytes) is not int
            or not 0 <= self.output_bytes <= MAX_APPROVED_CHECK_OUTPUT_BYTES
        ):
            raise ProtocolValueError("invalid_approved_check")
        if (
            type(self.subject_state_digest) is not str
            or not self.subject_state_digest.startswith("sha256:")
            or type(self.approval_commitment) is not str
            or not self.approval_commitment.startswith("sha256:")
            or type(self.result_digest) is not str
            or not self.result_digest.startswith("sha256:")
            or type(self.duration_ms) is not int
            or self.duration_ms < 0
        ):
            raise ProtocolValueError("invalid_approved_check")


def approval_commitment(approval_id: str, argv: Sequence[str], *, allow_network: bool) -> str:
    """Return the commitment for one exact approved argv (not freeform shell)."""

    return canonical_digest(
        {
            "format": APPROVED_CHECK_FORMAT,
            "approval_id": approval_id,
            "argv": tuple(argv),
            "allow_network": allow_network,
        }
    )


def approved_check_result_digest(
    status: ApprovedCheckStatus,
    outcome: ApprovedCheckOutcome,
    exit_status: int | None,
    output_digest: str | None,
    output_bytes: int,
    subject_state_digest: str,
    approval_commitment_value: str,
    duration_ms: int,
) -> str:
    """The digest an ``ApprovedCheckResult`` carries over exactly its own structural fields."""

    payload: dict[str, JsonValue] = {
        "format": APPROVED_CHECK_FORMAT,
        "status": status.value,
        "outcome": outcome.value,
        "exit_status": exit_status,
        "output_digest": output_digest,
        "output_bytes": output_bytes,
        "subject_state_digest": subject_state_digest,
        "approval_commitment": approval_commitment_value,
        "duration_ms": duration_ms,
    }
    return canonical_digest(payload)
