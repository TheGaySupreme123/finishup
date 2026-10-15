"""Simulated file ownership for non-root container layouts, on any runner.

A container image keeps ``/app`` root-owned and runs the agent as a non-root ``USER``; anything
root made for that user inside is the user's. A test cannot create a root-owned directory without
being root, so the runner keeps playing the user and the kernel's answer is rewritten instead:
``stat``, ``lstat`` and ``fstat`` report each chosen inode as owned by another uid. The superuser
is played by ``SUPERUSER`` (``foreign_write`` trusts it as root) and a second non-root account by
``OTHER``. Permission enforcement is not simulated: the runner can still write where the real
user could not, so a test pre-creates what root would have made for the user.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Final, cast

import pytest

from finishup.config import foreign_write

SUPERUSER: Final = os.geteuid() + 4242
OTHER: Final = os.geteuid() + 4343
_EXTRA_FIELDS: Final = (
    "st_atime",
    "st_mtime",
    "st_ctime",
    "st_atime_ns",
    "st_mtime_ns",
    "st_ctime_ns",
    "st_blksize",
    "st_blocks",
    "st_rdev",
    "st_flags",
    "st_gen",
    "st_birthtime",
    "st_birthtime_ns",
)


def _with_owner(facts: os.stat_result, uid: int) -> os.stat_result:
    values = list(cast(tuple[int, ...], tuple(facts)))
    values[4] = uid
    extra = {name: getattr(facts, name) for name in _EXTRA_FIELDS if hasattr(facts, name)}
    return os.stat_result(values, extra)


def present_owners(monkeypatch: pytest.MonkeyPatch, owners: Mapping[Path, int]) -> None:
    """Report each existing path in ``owners`` as owned by its uid, by inode, from now on."""

    monkeypatch.setattr(foreign_write, "_SUPERUSER_UID", SUPERUSER)
    identities: dict[tuple[int, int], int] = {}
    for path, uid in owners.items():
        facts = os.lstat(path)
        identities[(facts.st_dev, facts.st_ino)] = uid
    replaced: dict[object, object] = {}
    for name in ("stat", "lstat", "fstat"):
        real = cast(Callable[..., os.stat_result], getattr(os, name))

        def reported(
            *args: object, _real: Callable[..., os.stat_result] = real, **kwargs: object
        ) -> os.stat_result:
            facts = _real(*args, **kwargs)
            uid = identities.get((facts.st_dev, facts.st_ino))
            return facts if uid is None else _with_owner(facts, uid)

        replaced[real] = reported
        monkeypatch.setattr(os, name, reported)
    # Code that requires descriptor-relative primitives asks ``os.supports_*`` about the very
    # function objects; the stand-ins keep the capabilities of what they wrap.
    for capability in ("supports_dir_fd", "supports_fd", "supports_follow_symlinks"):
        members = set(cast(set[object], getattr(os, capability)))
        members.update(fake for real, fake in replaced.items() if real in members)
        monkeypatch.setattr(os, capability, members)


def root_owned_project(
    monkeypatch: pytest.MonkeyPatch,
    parent: Path,
    *,
    mode: int,
    made_for_user: tuple[str, ...] = (),
    other_owned: Mapping[str, int] | None = None,
) -> Path:
    """``<parent>/app`` owned by the superuser with ``mode``.

    ``made_for_user`` names directories root pre-created inside it for the user (owner-only);
    ``other_owned`` maps directory names another non-root account created to their mode.
    """

    root = parent.resolve() / "app"
    root.mkdir()
    for name in made_for_user:
        current = root
        for part in Path(name).parts:
            current /= part
            current.mkdir(mode=0o700, exist_ok=True)
            current.chmod(0o700)
    owners: dict[Path, int] = {root: SUPERUSER}
    for name, entry_mode in (other_owned or {}).items():
        entry = root / name
        entry.mkdir()
        entry.chmod(entry_mode)
        owners[entry] = OTHER
    root.chmod(mode)
    present_owners(monkeypatch, owners)
    return root
