"""The one refusal text for an installed runtime another account can write or owns.

Shared by the console entry (before the CLI graph loads), CLI service-unavailable failures and
setup. Standard library only. Terminal commands get the exact repair for this installation; hook
output, which a host may show to a model, carries no local path.
"""

from __future__ import annotations

import os
import shlex
import sys
from pathlib import Path


def _repair_paths() -> list[str]:
    """The installed environment, plus its base interpreter tree when this account owns it."""

    prefix = os.path.realpath(sys.prefix)
    try:
        from yoetz.adapters.release_runtime import installation_prefix

        prefix = os.path.realpath(installation_prefix())
    except Exception:  # noqa: BLE001 - fall back to this process's prefix
        pass
    paths = [prefix]
    try:
        executable = os.path.realpath(os.path.join(prefix, "bin", "python"))
        interpreter = os.path.dirname(os.path.dirname(executable))
        if (
            interpreter not in {prefix, os.sep}
            and not prefix.startswith(interpreter + os.sep)
            and os.stat(interpreter).st_uid == os.geteuid()
        ):
            paths.append(interpreter)
    except OSError:
        pass
    return paths


def foreign_write_refusal(token: str, *, hook: bool) -> str:
    """Name who can write the runtime and the exact repair; ends with a newline."""

    who = (
        "Every account on this machine"
        if token == "release_runtime_world_writable"
        else "Another account in a shared group"
    )
    head = f"{token}: {who} can modify the installed Yoetz runtime, so Yoetz will not run it. "
    if hook:
        return (
            head + "Run 'yoetz service run' in a terminal for the exact repair command; "
            "this hook did nothing.\n"
        )
    paths = _repair_paths()
    if not all(_printable(path) for path in paths):
        command = "chmod -R go-w <the Yoetz tool environment> <its Python installation>"
    else:
        command = shlex.join(["chmod", "-R", "go-w", *paths])
    return (
        head + "Remove group and other write access, then retry:\n"
        f"  {command}\n"
        "To keep later installs private, run 'umask 022' in the shell before 'uv tool install'.\n"
    )


def _printable(path: str) -> bool:
    return not any(ord(c) < 32 or ord(c) == 127 for c in path)


def _not_owned_facts() -> tuple[str | None, bool, bool]:
    """``(directory, exists, installation_is_mine)`` for this installation's retained runtimes."""

    try:
        from yoetz.adapters.release_runtime import installation_prefix, retained_runtime_directory

        prefix = Path(os.path.realpath(installation_prefix()))
        directory = retained_runtime_directory(prefix)
        mine = not hasattr(os, "geteuid") or os.stat(prefix).st_uid == os.geteuid()
        return os.fspath(directory), os.path.lexists(directory), mine
    except Exception:  # noqa: BLE001 - the text still says what is needed without the facts
        return None, False, False


def not_owned_refusal(*, hook: bool) -> str:
    """The retained-runtime directory is not this account's: name it and the real repair.

    Ends with a newline. Hook output carries no local path.
    """

    head = (
        "release_runtime_not_owned: Yoetz runs from a private copy kept in a directory beside "
        "this installation, and that directory must belong to the account running Yoetz. "
    )
    if hook:
        return (
            head + "Here it belongs to another account or cannot be created. Run 'yoetz service "
            "run' in a terminal for the details; this hook did nothing.\n"
        )
    directory, exists, mine = _not_owned_facts()
    shown = (
        directory
        if directory is not None and _printable(directory)
        else "<the directory beside the Yoetz tool environment>"
    )
    situation = (
        "That directory belongs to another account:"
        if exists
        else "This account cannot create that directory:"
    )
    if mine and exists:
        repair = (
            "This installation is yours, so the directory was made by someone else (for "
            "example with sudo). Remove it, or have its owner remove it, then retry; Yoetz "
            "recreates it as yours (mode 0700).\n"
        )
    elif mine:
        repair = (
            "Have the owner of the directory that holds this installation create it owned by "
            "this account (mode 0700), then retry.\n"
        )
    else:
        repair = (
            "This installation belongs to another account. Install Yoetz as this account, then "
            "connect your hosts again from that installation; or have the installation's owner "
            "create that directory for this account alone (mode 0700) before anyone runs "
            "Yoetz from it.\n"
        )
    return head + situation + "\n" + f"  {shown}\n" + repair


def runtime_refusal(token: str, *, hook: bool) -> str:
    """The refusal text for any ownership token the installed runtime reports."""

    if token == "release_runtime_not_owned":
        return not_owned_refusal(hook=hook)
    return foreign_write_refusal(token, hook=hook)


def installed_runtime_refusal_text() -> tuple[str, str] | None:
    """``(token, text)`` when this installation's runtime is refused for its ownership."""

    if os.name == "nt":
        return None
    try:
        from yoetz.adapters.release_runtime import installed_runtime_refusal

        error = installed_runtime_refusal()
    except Exception:  # noqa: BLE001 - a probe never replaces the caller's own failure
        return None
    if error is None:
        return None
    token = str(error)
    return token, runtime_refusal(token, hook=False)


def connect_refusal() -> tuple[str, str] | None:
    """``(token, next step)`` when no host may be connected to this installation's runtime.

    Every connect path asks this before it writes a registration: each host would launch this
    runtime and every launch would be refused. Disconnect and status never ask, so the way out
    and the read-only view stay open. The next step is the refusal text without its token.
    """

    refusal = installed_runtime_refusal_text()
    if refusal is None:
        return None
    token, text = refusal
    return token, text.split(": ", 1)[1].rstrip("\n")
