"""Enforcing process sandbox boundary for approved checks."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Protocol

__all__ = [
    "CheckSandboxAvailability",
    "CheckSandboxLaunch",
    "CheckSandboxPort",
    "CheckSandboxStatus",
]


class CheckSandboxStatus(str, Enum):  # noqa: UP042 - exact wire enum
    READY = "ready"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True, slots=True)
class CheckSandboxLaunch:
    """Prepared argv/env for one sandboxed check execution."""

    argv: tuple[str, ...]
    env: Mapping[str, str]
    cwd: Path
    status: CheckSandboxStatus
    network_isolated: bool

    def __post_init__(self) -> None:
        if type(self.argv) is not tuple or not self.argv:
            raise ValueError("check_sandbox_invalid")
        if type(self.status) is not CheckSandboxStatus:
            raise ValueError("check_sandbox_invalid")
        if type(self.network_isolated) is not bool:
            raise ValueError("check_sandbox_invalid")
        if self.status is CheckSandboxStatus.UNAVAILABLE and self.network_isolated:
            raise ValueError("check_sandbox_invalid")


@dataclass(frozen=True, slots=True)
class CheckSandboxAvailability:
    """One host-level answer to "can a network-denied check run here?" (issue #720).

    ``prepare`` answers per run and fails closed; this is the same decision reported once, with
    the dependency named, so setup diagnostics can say *why* before a check is ever approved.
    """

    status: CheckSandboxStatus
    mechanism: str
    reason: str
    remediation: str

    def __post_init__(self) -> None:
        if type(self.status) is not CheckSandboxStatus:
            raise ValueError("check_sandbox_invalid")
        for value in (self.mechanism, self.reason, self.remediation):
            if type(value) is not str:
                raise ValueError("check_sandbox_invalid")
        if not self.mechanism or not self.reason:
            raise ValueError("check_sandbox_invalid")

    def as_json(self) -> dict[str, str]:
        return {
            "mechanism": self.mechanism,
            "reason": self.reason,
            "remediation": self.remediation,
            "status": self.status.value,
        }


class CheckSandboxPort(Protocol):
    """Wrap an approved argv under an enforcing no-network sandbox when available."""

    def prepare(
        self,
        *,
        argv: Sequence[str],
        cwd: Path,
        env: Mapping[str, str],
        deny_network: bool,
    ) -> CheckSandboxLaunch: ...
