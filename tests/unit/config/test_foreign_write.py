"""Group-write is accepted only for the owner's user-private group; world-write never is."""

from __future__ import annotations

import os
from collections.abc import Generator
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from yoetz.config import foreign_write


@dataclass(frozen=True)
class _Account:
    pw_name: str
    pw_uid: int
    pw_gid: int


@dataclass(frozen=True)
class _Group:
    gr_name: str
    gr_gid: int
    gr_mem: list[str] = field(default_factory=list[str])


class _Pwd:
    def __init__(self, accounts: list[_Account], *, enumerable: bool = True) -> None:
        self.accounts = accounts
        self.enumerable = enumerable

    def getpwuid(self, uid: int) -> _Account:
        for account in self.accounts:
            if account.pw_uid == uid:
                return account
        raise KeyError(uid)

    def getpwall(self) -> list[_Account]:
        if not self.enumerable:
            raise OSError("enumeration unavailable")
        return list(self.accounts)


class _Grp:
    def __init__(self, groups: list[_Group]) -> None:
        self.groups = groups

    def getgrgid(self, gid: int) -> _Group:
        for group in self.groups:
            if group.gr_gid == gid:
                return group
        raise KeyError(gid)


ALICE = _Account("alice", 1001, 1001)
BOB = _Account("bob", 1002, 1002)


@pytest.fixture(autouse=True)
def fresh_cache() -> Generator[None]:
    foreign_write.clear_cache()
    yield
    foreign_write.clear_cache()


def _databases(
    monkeypatch: pytest.MonkeyPatch,
    accounts: list[_Account],
    groups: list[_Group],
    *,
    enumerable: bool = True,
) -> None:
    monkeypatch.setattr(foreign_write, "_pwd", _Pwd(accounts, enumerable=enumerable))
    monkeypatch.setattr(foreign_write, "_grp", _Grp(groups))


def _facts(mode: int, *, uid: int = 1001, gid: int = 1001) -> os.stat_result:
    return os.stat_result((mode, 0, 0, 1, uid, gid, 0, 0, 0, 0))


def test_user_private_group_write_is_owner_only(monkeypatch: pytest.MonkeyPatch) -> None:
    # Ubuntu/Fedora default: alice's primary group "alice" (gid 1001) has nobody else.
    _databases(monkeypatch, [ALICE, BOB], [_Group("alice", 1001), _Group("bob", 1002)])
    assert foreign_write.foreign_write(_facts(0o40775)) is None
    assert foreign_write.foreign_write(_facts(0o100664)) is None
    assert not foreign_write.writable_by_others(_facts(0o100664))


def test_owner_listed_as_own_group_member_is_still_private(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _databases(monkeypatch, [ALICE], [_Group("alice", 1001, ["alice"])])
    assert foreign_write.foreign_write(_facts(0o100664)) is None


def test_world_write_is_always_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    _databases(monkeypatch, [ALICE], [_Group("alice", 1001)])
    assert foreign_write.foreign_write(_facts(0o100666)) == "world"
    assert foreign_write.foreign_write(_facts(0o100646)) == "world"


@pytest.mark.parametrize(
    "groups, accounts",
    [
        # A supplementary member can write through the group.
        ([_Group("alice", 1001, ["bob"])], [ALICE, BOB]),
        # Another account uses alice's group as its primary group.
        ([_Group("alice", 1001)], [ALICE, _Account("carol", 1003, 1001)]),
        # A shared group such as "users" or macOS "staff": not named like the owner.
        ([_Group("users", 1001)], [ALICE]),
    ],
    ids=["supplementary-member", "foreign-primary", "shared-name"],
)
def test_shared_group_write_is_refused(
    monkeypatch: pytest.MonkeyPatch, groups: list[_Group], accounts: list[_Account]
) -> None:
    _databases(monkeypatch, accounts, groups)
    assert foreign_write.foreign_write(_facts(0o100664)) == "group"


def test_group_other_than_the_owners_primary_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    # bob's private group on a file alice owns lets bob write it.
    _databases(monkeypatch, [ALICE, BOB], [_Group("alice", 1001), _Group("bob", 1002)])
    assert foreign_write.foreign_write(_facts(0o100664, gid=1002)) == "group"


@pytest.mark.parametrize(
    "accounts, groups, enumerable",
    [
        ([], [_Group("alice", 1001)], True),  # owner unknown
        ([ALICE], [], True),  # group unknown
        ([ALICE], [_Group("alice", 1001)], False),  # accounts cannot be enumerated
    ],
    ids=["unknown-owner", "unknown-group", "no-enumeration"],
)
def test_unestablished_membership_is_treated_as_shared(
    monkeypatch: pytest.MonkeyPatch,
    accounts: list[_Account],
    groups: list[_Group],
    enumerable: bool,
) -> None:
    _databases(monkeypatch, accounts, groups, enumerable=enumerable)
    assert foreign_write.foreign_write(_facts(0o100664)) == "group"


def test_without_posix_account_databases_group_write_is_shared(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(foreign_write, "_pwd", None)
    monkeypatch.setattr(foreign_write, "_grp", None)
    assert foreign_write.foreign_write(_facts(0o100664)) == "group"
    assert foreign_write.foreign_write(_facts(0o100644)) is None


def test_a_group_gaining_a_member_is_noticed_after_the_cache_expires(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    group = _Group("alice", 1001)
    _databases(monkeypatch, [ALICE, BOB], [group])
    now = [100.0]
    monkeypatch.setattr(foreign_write.time, "monotonic", lambda: now[0])
    assert foreign_write.foreign_write(_facts(0o100664)) is None
    group.gr_mem.append("bob")
    now[0] += foreign_write._TTL_SECONDS  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    assert foreign_write.foreign_write(_facts(0o100664)) == "group"


def test_real_account_database_matches_the_current_user(tmp_path: Path) -> None:
    # No fakes: a file this account creates with g+w is accepted exactly when its group is
    # this account's private group by the local databases.
    path = tmp_path / "f"
    path.write_text("x")
    path.chmod(0o664)
    facts = path.stat()
    expected = foreign_write._lookup_private_group(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        facts.st_uid, facts.st_gid
    )
    assert foreign_write.writable_by_others(facts) is not expected
