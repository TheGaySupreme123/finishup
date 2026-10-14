"""Whether a filesystem object can be written by anyone other than its owner.

A mode bit is not the security question; the people behind it are. World-write always lets
another account write. Group-write lets another account write unless the group is the owner's
user-private group: the owner's primary group, named like the owner, with no supplementary
members and no other account using it as a primary group. That is the default layout for normal
accounts on Ubuntu, Debian, Fedora and RHEL (``USERGROUPS_ENAB yes``), where the default umask is
0002, so every file an ordinary install creates is group-writable by a group of one.

Privacy is accepted only when membership is provably complete, which the C library's account
lookups cannot show: a directory service (SSSD, LDAP, NIS, winbind) may not enumerate accounts
and may report a populated group as empty. So the answer comes from the local files alone, and
only when ``/etc/nsswitch.conf`` serves the ``passwd`` and ``group`` databases (and
``initgroups`` when named) exclusively from ``files`` and ``systemd``. ``systemd`` is admitted
because on a stock system it only adds dynamic service users (gids 61184-65519, never a person's
private group); any userdb drop-in record or userdb service beyond dynamic users (systemd-homed,
for example) makes the answer unprovable. ``/etc/gshadow`` is read when readable; an ordinary
account cannot read it, and its member list is kept in step with ``/etc/group`` by the account
tools. A group password set with ``gpasswd`` is outside this rule. No ``nsswitch.conf`` (macOS),
NIS ``+``/``-`` compat lines, a duplicate gid, or anything unreadable counts as shared.

Only the standard library is imported: the installed launcher calls this before the CLI graph.
"""

from __future__ import annotations

import os
import re
import stat
import time
from pathlib import Path
from typing import Final, Literal

ForeignWrite = Literal["group", "world"]
GROUP: Final[ForeignWrite] = "group"
WORLD: Final[ForeignWrite] = "world"

# The filesystem root the account files are read under; tests point it at a fixture tree.
_ROOT: Path = Path("/")
_LOCAL_SOURCES: Final = frozenset({"files", "systemd"})
_ACTION: Final = re.compile(r"\[[^\]]*\]")
_DYNAMIC_GIDS: Final = range(61184, 65520)
# Userdb services that never describe a person's group membership.
_SAFE_USERDB_SERVICES: Final = frozenset(
    {
        "io.systemd.DynamicUser",
        "io.systemd.Multiplexer",
        "io.systemd.NameServiceSwitch",
        "io.systemd.DropIn",
    }
)
_USERDB_DROP_INS: Final = (
    "etc/userdb",
    "run/userdb",
    "run/host/userdb",
    "usr/lib/userdb",
    "usr/local/lib/userdb",
)
_MAX_ACCOUNT_FILE: Final = 16_777_216


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


def _read(relative: str) -> str | None:
    """A local account file's text, or None when absent, unreadable or implausibly large."""

    try:
        with (_ROOT / relative).open("rb") as stream:
            data = stream.read(_MAX_ACCOUNT_FILE + 1)
    except OSError:
        return None
    if len(data) > _MAX_ACCOUNT_FILE:
        return None
    return data.decode("utf-8", errors="replace")


def _records(text: str) -> list[list[str]] | None:
    """Colon records; None when a NIS compat line (``+``/``-``) imports unseen accounts."""

    records: list[list[str]] = []
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line[0] in "+-":
            return None
        records.append(line.split(":"))
    return records


def _local_databases_only() -> bool:
    """Whether every account and group lookup is answered from local files (see module doc)."""

    text = _read("etc/nsswitch.conf")
    if text is None:
        return False
    sources: dict[str, list[str]] = {}
    for line in text.splitlines():
        line = line.split("#", 1)[0]
        if ":" not in line:
            continue
        database, _, rest = line.partition(":")
        sources[database.strip()] = _ACTION.sub(" ", rest).split()
    required = ["passwd", "group"] + (["initgroups"] if "initgroups" in sources else [])
    for database in required:
        named = sources.get(database)
        if not named or any(source not in _LOCAL_SOURCES for source in named):
            return False
    if not any("systemd" in sources[database] for database in required):
        return True
    services: set[str]
    try:
        services = {entry.name for entry in (_ROOT / "run/systemd/userdb").iterdir()}
    except FileNotFoundError:
        services = set()
    except OSError:
        return False
    if services - _SAFE_USERDB_SERVICES:
        return False
    for relative in _USERDB_DROP_INS:
        try:
            if any((_ROOT / relative).iterdir()):
                return False
        except FileNotFoundError:
            continue
        except OSError:
            return False
    return True


def _lookup_private_group(uid: int, gid: int) -> bool:
    if gid in _DYNAMIC_GIDS or not _local_databases_only():
        return False
    passwd_text, group_text = _read("etc/passwd"), _read("etc/group")
    if passwd_text is None or group_text is None:
        return False
    accounts, groups = _records(passwd_text), _records(group_text)
    if accounts is None or groups is None:
        return False
    try:
        owners = [entry for entry in accounts if int(entry[2]) == uid]
        if not owners:
            return False
        owner_name, owner_gid = owners[0][0], int(owners[0][3])
        if owner_gid != gid:
            return False
        if any(int(entry[3]) == gid and int(entry[2]) != uid for entry in accounts):
            return False
        matching = [entry for entry in groups if int(entry[2]) == gid]
    except IndexError, ValueError:
        return False
    if len(matching) != 1 or len(matching[0]) < 4 or matching[0][0] != owner_name:
        return False
    if {member.strip() for member in matching[0][3].split(",") if member.strip()} - {owner_name}:
        return False
    shadow_text = _read("etc/gshadow")
    if shadow_text is not None:
        shadow = _records(shadow_text)
        if shadow is None:
            return False
        for entry in shadow:
            if entry[0] != owner_name:
                continue
            if len(entry) < 4 or entry[1] not in {"", "!", "*", "!!", "!*"}:
                return False
            people = {name.strip() for field in entry[2:4] for name in field.split(",")}
            if people - {"", owner_name}:
                return False
    return True


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
