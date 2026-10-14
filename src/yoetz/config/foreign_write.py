"""Whether a filesystem object can be written by anyone other than its owner.

A mode bit is not the security question; the people behind it are. World-write always lets
another account write. Group-write lets another account write unless the group is the owner's
user-private group: the owner's primary group, named like the owner, with no supplementary
members and no other account using it as a primary group. That is the default layout for normal
accounts on Ubuntu, Debian, Fedora and RHEL (``USERGROUPS_ENAB yes``), where the default umask is
0002, so every file an ordinary install creates is group-writable by a group of one.

Anything that cannot be established from the local account databases counts as shared: a
missing group or account, a group whose name differs from the owner's, a supplementary member,
or another enumerated account with that primary group. Accounts a directory service does not
enumerate cannot be seen; a deployment that gives a directory account someone else's private
group as its primary group is outside this rule, the same as one that shares a home directory.

Only the standard library is imported: the installed launcher calls this before the CLI graph.
"""

from __future__ import annotations

import os
import stat
import time
from typing import Final, Literal

ForeignWrite = Literal["group", "world"]
GROUP: Final[ForeignWrite] = "group"
WORLD: Final[ForeignWrite] = "world"

try:  # POSIX only; on other platforms nothing is treated as a private group.
    import grp as _grp
    import pwd as _pwd
except ImportError:  # pragma: no cover - non-POSIX
    _grp = None
    _pwd = None


# A tree walk asks the same question thousands of times; a long-lived service must still notice
# a group gaining a member, so answers live for a few seconds only.
_TTL_SECONDS: Final = 5.0
_answers: dict[tuple[int, int], tuple[float, bool]] = {}


def clear_cache() -> None:
    _answers.clear()


def owner_private_group(uid: int, gid: int) -> bool:
    """Whether ``gid`` is ``uid``'s user-private group with no other member."""

    now = time.monotonic()
    cached = _answers.get((uid, gid))
    if cached is not None and now - cached[0] < _TTL_SECONDS:
        return cached[1]
    if len(_answers) > 64:
        _answers.clear()
    answer = _lookup_private_group(uid, gid)
    _answers[(uid, gid)] = (now, answer)
    return answer


def _lookup_private_group(uid: int, gid: int) -> bool:
    if _grp is None or _pwd is None:
        return False
    try:
        owner = _pwd.getpwuid(uid)
        group = _grp.getgrgid(gid)
    except KeyError, OSError:
        return False
    if owner.pw_gid != gid or group.gr_name != owner.pw_name:
        return False
    if any(member != owner.pw_name for member in group.gr_mem):
        return False
    try:
        accounts = _pwd.getpwall()
    except OSError:
        return False
    return not any(entry.pw_gid == gid and entry.pw_uid != uid for entry in accounts)


def foreign_write(facts: os.stat_result) -> ForeignWrite | None:
    """``"world"`` or ``"group"`` when another account may write; ``None`` when only the owner."""

    mode = stat.S_IMODE(facts.st_mode)
    if mode & stat.S_IWOTH:
        return WORLD
    if mode & stat.S_IWGRP and not owner_private_group(facts.st_uid, facts.st_gid):
        return GROUP
    return None


def writable_by_others(facts: os.stat_result) -> bool:
    """Drop-in for ``facts.st_mode & 0o022`` that accepts the owner's private group."""

    return foreign_write(facts) is not None
