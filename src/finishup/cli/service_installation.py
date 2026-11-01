"""Which folders the everyday installation uses, and the refusal when they cannot be chosen.

An installation first made as Yoetz is adopted in place (ADR-048): its data stays in the
Yoetz-era platform folders and nothing is moved, copied, or renamed. The released JSON reports
(``yoetz.isolation-report/1``, setup status 2.0.0) are closed, so that fact reaches people as a
human line on status surfaces instead of a new field.

When the folders cannot be chosen at all -- data under both product names, or an unusable
isolation root -- the control client refuses before touching any endpoint and keeps the closed
path-safety token (``finishup.service.client.path_refusal_reason``). The renderers here name that
token, its remedy, and its continuation instead of reporting an absent service. Nothing here
includes a path.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Final, Literal

from finishup.cli.exits import (
    INSTANCE_PUBLIC_CODES,
    UPGRADING_FROM_YOETZ_GUIDE,
    exit_code_for,
    remediation_message,
)
from finishup.config.paths import PathSafetyError, installation_naming, isolated_root
from finishup.protocol.canonical import JsonValue
from finishup.protocol.errors import PublicErrorCode

__all__ = [
    "LEGACY_FOLDERS_NOTE",
    "InstallationFolders",
    "installation_folders",
    "installation_naming_line",
    "path_refusal_agent_message",
    "path_refusal_failure",
    "report_installation_naming",
]

# ``finishup``: the FinishUP platform folders. ``legacy_yoetz``: the Yoetz-era folders, adopted
# in place. ``isolated``: an isolation root, which never uses the platform folders.
type InstallationFolders = Literal["finishup", "legacy_yoetz", "isolated"]

LEGACY_FOLDERS_NOTE: Final = (
    "installation: this install still uses its Yoetz-era folders in place. Nothing was moved, "
    "copied, or renamed, and those folders hold its FinishUP data, so keep them. Read more: "
    + UPGRADING_FROM_YOETZ_GUIDE
)


def installation_folders() -> InstallationFolders:
    """Name which folders this process's installation uses, as a closed token.

    Raises the bounded ``PathSafetyError`` when they cannot be chosen: an isolation root that is
    set but unusable, or ambient data under both product names (``installation_root_ambiguous``).
    """

    if isolated_root() is not None:
        return "isolated"
    return installation_naming()


def installation_naming_line() -> str | None:
    """The human status line for an installation adopted in place, or None.

    None for FinishUP folders and isolated roots, which need no note, and when the folders cannot
    be chosen: that refusal is reported by the command's own failure path, never as a status line.
    """

    try:
        folders = installation_folders()
    except PathSafetyError:
        return None
    return LEGACY_FOLDERS_NOTE if folders == "legacy_yoetz" else None


def report_installation_naming(stderr_writer: Callable[[str], None]) -> None:
    """Write the adopted-in-place note to stderr for a human status render, when it applies.

    stderr keeps ``service status`` stdout (JSON when it is not a terminal) byte-identical.
    """

    line = installation_naming_line()
    if line is not None:
        stderr_writer(line)


def _refusal_lines(reason: str) -> str:
    from finishup.cli.instance import instance_failure_line

    # The same bounded line ``finishup service run`` prints for this refusal.
    return instance_failure_line(PathSafetyError(reason))


def path_refusal_failure(
    reason: str,
    *,
    json_output: bool,
    stderr_writer: Callable[[str], None],
    stdout_writer: Callable[[JsonValue], None],
) -> int:
    """Report a connection refused because FinishUP's local folders cannot be used safely.

    ``reason`` is the closed token from ``path_refusal_reason``. The token, its remedy, and its
    continuation go to stderr; ``--json`` adds the same machine-readable shape as the other
    control failures. Returns the process exit code (unsafe storage: 20).
    """

    from finishup.cli.render import local_recovery_json

    code = INSTANCE_PUBLIC_CODES.get(reason, PublicErrorCode.STORAGE_UNSAFE)
    stderr_writer(_refusal_lines(reason))
    if json_output:
        payload: dict[str, JsonValue] = {
            "ok": False,
            "public_code": code.value,
            "reason": reason,
            "retryable": False,
        }
        recovery = local_recovery_json(reason)
        if recovery is not None:
            payload["recovery"] = recovery
        stdout_writer(payload)
    return exit_code_for(code)


def path_refusal_agent_message(reason: str) -> str:
    """The agent-facing sentence for the same refusal over MCP, naming the token and its remedy."""

    remedy = remediation_message(reason)
    head = (
        f"FinishUP's local folders cannot be used safely ({reason}), so no service was reached "
        "or started and nothing was recorded. Retrying fails the same way until the user "
        "resolves this on a local terminal; do not run service lifecycle commands to work "
        "around it."
    )
    # The remedy goes last: it may end in the upgrade guide's address, which stays clickable.
    return head if remedy is None else f"{head} Tell the user: {remedy}"
