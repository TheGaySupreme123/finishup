"""Exact-byte project check policy parsing and digest-bound authority."""

from __future__ import annotations

import hashlib
import os
import stat
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Final, cast

from yoetz.adapters.approved_checks import (
    ApprovedCheckApproval,
    approval_commitment,
)
from yoetz.protocol.errors import ProtocolValueError

__all__ = [
    "CHECK_POLICY_FORMAT",
    "CHECK_POLICY_PATH",
    "ObservationCheckPolicy",
    "ObservationCheckPolicyAbsent",
    "load_observation_check_policy",
    "parse_observation_check_policy",
    "raw_policy_digest",
]

CHECK_POLICY_FORMAT: Final = "yoetz.approved-check-policy/1"
CHECK_POLICY_PATH: Final = Path(".yoetz/checks.toml")
_MAX_POLICY_BYTES: Final = 256 * 1024


@dataclass(frozen=True, slots=True)
class ObservationCheckPolicy:
    raw_digest: str
    checks: tuple[ApprovedCheckApproval, ...]

    def __post_init__(self) -> None:
        if (
            type(self.raw_digest) is not str
            or not self.raw_digest.startswith("sha256:")
            or len(self.raw_digest) != 71
            or type(self.checks) is not tuple
            or not self.checks
        ):
            raise ProtocolValueError("invalid_approved_check_policy")
        ids = [item.approval_id for item in self.checks]
        if ids != sorted(set(ids), key=str.encode):
            raise ProtocolValueError("invalid_approved_check_policy")


class ObservationCheckPolicyAbsent(ProtocolValueError):
    """The workspace has no `.yoetz/checks.toml`: the optional feature is not configured.

    Approved workspace checks are an opt-in owner feature, so absence is the ordinary state, not a
    policy fault. It subclasses the invalid-policy failure so every caller that only needs "no
    usable policy" keeps failing closed, while callers that report state can tell the two apart.
    """

    __slots__ = ()

    def __init__(self) -> None:
        super().__init__("invalid_approved_check_policy")


def raw_policy_digest(raw: bytes) -> str:
    if type(raw) is not bytes or not raw or len(raw) > _MAX_POLICY_BYTES:
        raise ProtocolValueError("invalid_approved_check_policy")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def parse_observation_check_policy(raw: bytes) -> ObservationCheckPolicy:
    """Parse the fixed policy schema while binding trust to the exact raw bytes."""

    digest = raw_policy_digest(raw)
    try:
        document = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise ProtocolValueError("invalid_approved_check_policy") from exc
    if set(document) != {"format", "checks"} or document.get("format") != CHECK_POLICY_FORMAT:
        raise ProtocolValueError("invalid_approved_check_policy")
    source = document.get("checks")
    if type(source) is not list or not source:
        raise ProtocolValueError("invalid_approved_check_policy")
    checks: list[ApprovedCheckApproval] = []
    for raw_check in cast(list[object], source):
        if type(raw_check) is not dict:
            raise ProtocolValueError("invalid_approved_check_policy")
        check = cast(dict[str, object], raw_check)
        if set(check) != {"id", "argv", "timeout_seconds", "network"}:
            raise ProtocolValueError("invalid_approved_check_policy")
        check_id = check["id"]
        argv_raw = check["argv"]
        timeout_raw = check["timeout_seconds"]
        network = check["network"]
        if type(check_id) is not str or type(argv_raw) is not list:
            raise ProtocolValueError("invalid_approved_check_policy")
        argv_values = cast(list[object], argv_raw)
        if any(type(item) is not str for item in argv_values):
            raise ProtocolValueError("invalid_approved_check_policy")
        if (
            type(timeout_raw) not in {int, float}
            or isinstance(timeout_raw, bool)
            or type(network) is not bool
        ):
            raise ProtocolValueError("invalid_approved_check_policy")
        argv = tuple(cast(str, item) for item in argv_values)
        timeout_seconds = float(cast(int | float, timeout_raw))
        checks.append(
            ApprovedCheckApproval(
                approval_id=check_id,
                argv=argv,
                allow_network=network,
                timeout_seconds=timeout_seconds,
                approval_commitment=approval_commitment(check_id, argv, allow_network=network),
            )
        )
    checks.sort(key=lambda item: item.approval_id.encode())
    return ObservationCheckPolicy(digest, tuple(checks))


def load_observation_check_policy(workspace: Path) -> tuple[ObservationCheckPolicy, bytes]:
    """Read the fixed policy beneath a validated root without following symlinks."""

    if workspace.is_symlink():
        raise ProtocolValueError("invalid_approved_check_policy")
    root = workspace.resolve(strict=True)
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0)
    file_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    root_fd = policy_dir_fd = policy_fd = -1
    try:
        root_fd = os.open(root, directory_flags | nofollow)
        try:
            policy_dir_fd = os.open(".yoetz", directory_flags | nofollow, dir_fd=root_fd)
            policy_fd = os.open("checks.toml", file_flags | nofollow, dir_fd=policy_dir_fd)
        except FileNotFoundError as exc:
            # Only a genuinely missing entry is "absent"; a symlink, wrong type, or unreadable
            # file still fails as an invalid policy below.
            raise ObservationCheckPolicyAbsent() from exc
        facts = os.fstat(policy_fd)
        if not stat.S_ISREG(facts.st_mode) or not 0 < facts.st_size <= _MAX_POLICY_BYTES:
            raise ProtocolValueError("invalid_approved_check_policy")
        chunks: list[bytes] = []
        remaining = _MAX_POLICY_BYTES + 1
        while remaining:
            chunk = os.read(policy_fd, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) != facts.st_size or len(raw) > _MAX_POLICY_BYTES:
            raise ProtocolValueError("invalid_approved_check_policy")
    except OSError as exc:
        raise ProtocolValueError("invalid_approved_check_policy") from exc
    finally:
        for descriptor in (policy_fd, policy_dir_fd, root_fd):
            if descriptor >= 0:
                os.close(descriptor)
    return parse_observation_check_policy(raw), raw
