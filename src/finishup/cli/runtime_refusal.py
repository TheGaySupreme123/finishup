"""The one refusal text for an installed runtime another account can write.

Shared by the console entry (before the CLI graph loads), CLI service-unavailable failures and
setup. Standard library only. Terminal commands get the exact repair command for this
installation; hook output, which a host may show to a model, carries no local path.
"""

from __future__ import annotations

import os
import shlex
import sys


def _repair_paths() -> list[str]:
    """The installed environment, plus its base interpreter tree when this account owns it."""

    prefix = os.path.realpath(sys.prefix)
    try:
        from finishup.adapters.release_runtime import installation_prefix

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
    head = (
        f"{token}: {who} can modify the installed FinishUP runtime, so FinishUP will not run it. "
    )
    if hook:
        return (
            head + "Run 'finishup service run' in a terminal for the exact repair command; "
            "this hook did nothing.\n"
        )
    paths = _repair_paths()
    if any(any(ord(c) < 32 or ord(c) == 127 for c in path) for path in paths):
        command = "chmod -R go-w <the FinishUP tool environment> <its Python installation>"
    else:
        command = shlex.join(["chmod", "-R", "go-w", *paths])
    return (
        head + "Remove group and other write access, then retry:\n"
        f"  {command}\n"
        "To keep later installs private, run 'umask 022' in the shell before 'uv tool install'.\n"
    )


def installed_runtime_refusal_text() -> tuple[str, str] | None:
    """``(token, text)`` when this installation's runtime is refused for foreign write."""

    if os.name == "nt":
        return None
    try:
        from finishup.adapters.release_runtime import installed_runtime_refusal

        error = installed_runtime_refusal()
    except Exception:  # noqa: BLE001 - a probe never replaces the caller's own failure
        return None
    if error is None:
        return None
    token = str(error)
    return token, foreign_write_refusal(token, hook=False)
