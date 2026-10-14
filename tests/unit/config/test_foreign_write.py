"""Group-write is owner-only only when local files prove the group is the owner's alone."""

from __future__ import annotations

import os
from collections.abc import Generator
from pathlib import Path

import pytest

from finishup.config import foreign_write

LOCAL_NSS = "passwd: files systemd\ngroup: files systemd\nshadow: files systemd\n"
PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "alice:x:1001:1001::/home/alice:/bin/bash\n"
    "bob:x:1002:1002::/home/bob:/bin/bash\n"
)
GROUP = "root:x:0:\nalice:x:1001:\nbob:x:1002:\n"


@pytest.fixture(autouse=True)
def fresh_cache() -> Generator[None]:
    foreign_write.clear_cache()
    yield
    foreign_write.clear_cache()


def _tree(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    nss: str | None = LOCAL_NSS,
    passwd: str = PASSWD,
    group: str = GROUP,
    gshadow: str | None = None,
    userdb_services: tuple[str, ...] = ("io.systemd.DynamicUser",),
    drop_in: str | None = None,
) -> Path:
    root = tmp_path / "root"
    (root / "etc").mkdir(parents=True)
    if nss is not None:
        (root / "etc/nsswitch.conf").write_text(nss)
    (root / "etc/passwd").write_text(passwd)
    (root / "etc/group").write_text(group)
    if gshadow is not None:
        (root / "etc/gshadow").write_text(gshadow)
    (root / "run/systemd/userdb").mkdir(parents=True)
    for service in userdb_services:
        (root / "run/systemd/userdb" / service).write_text("")
    if drop_in is not None:
        (root / "etc/userdb").mkdir()
        (root / "etc/userdb" / drop_in).write_text("{}")
    monkeypatch.setattr(foreign_write, "_ROOT", root)
    return root


def _facts(mode: int, *, uid: int = 1001, gid: int = 1001) -> os.stat_result:
    return os.stat_result((mode, 0, 0, 1, uid, gid, 0, 0, 0, 0))


def test_user_private_group_from_local_files_is_owner_only(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # Ubuntu 24.04's stock nsswitch.conf and userdb, with alice's group of one.
    _tree(monkeypatch, tmp_path)
    assert foreign_write.foreign_write(_facts(0o40775)) is None
    assert foreign_write.foreign_write(_facts(0o100664)) is None
    assert not foreign_write.writable_by_others(_facts(0o100664))


@pytest.mark.parametrize(
    "nss",
    [
        "passwd: files\ngroup: files\n",
        "passwd: files [NOTFOUND=return] systemd\ngroup:files systemd # comment\n",
        "passwd: files systemd\ngroup: files systemd\ninitgroups: files\n",
        # glibc takes whitespace instead of the colon after the database name.
        "passwd files systemd\ngroup\tfiles\n  initgroups files # trailing\n",
        "passwd: files\npasswd: files systemd\ngroup: files\n",
        # glibc consumes the whole run of whitespace and colons after the name.
        "passwd : files\ngroup :: files systemd\n",
        "passwd: files [!UNAVAIL=return] systemd\ngroup: files [ SUCCESS = merge ] systemd\n",
        "passwd: files\r\ngroup: files\r\n",
    ],
    ids=[
        "files-only",
        "action-tokens",
        "local-initgroups",
        "colon-less",
        "local-duplicates",
        "space-before-colon",
        "action-grammar",
        "crlf",
    ],
)
def test_local_only_switch_variants_are_accepted(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, nss: str
) -> None:
    _tree(monkeypatch, tmp_path, nss=nss)
    assert foreign_write.foreign_write(_facts(0o100664)) is None


def test_owner_listed_as_own_group_member_is_still_private(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _tree(monkeypatch, tmp_path, group="alice:x:1001:alice\n")
    assert foreign_write.foreign_write(_facts(0o100664)) is None


def test_world_write_is_always_refused(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _tree(monkeypatch, tmp_path)
    assert foreign_write.foreign_write(_facts(0o100666)) == "world"
    assert foreign_write.foreign_write(_facts(0o100646)) == "world"


@pytest.mark.parametrize(
    "nss",
    [
        # SSSD/LDAP may not enumerate and may report a populated group as empty
        # (ignore_group_members=true): bob's hidden membership is invisible locally.
        "passwd: files sss\ngroup: files sss\n",
        "passwd: files systemd\ngroup: files ldap\n",
        "passwd: compat\ngroup: compat\n",
        "passwd: files winbind\ngroup: files winbind\n",
        "passwd: files\ngroup: files\ninitgroups: files sss\n",
        "passwd: files\n",
        "",
        # glibc accepts whitespace for the colon: these lines are live, not comments.
        "passwd: files\ngroup: files\ninitgroups files sss\n",
        "passwd: files\ngroup: files\ngroup\tsss\n",
        "passwd files sss\ngroup: files\n",
        # glibc 2.33+ keeps the last entry for a database, older releases the first; any
        # remote entry for a relevant database is decisive either way.
        "passwd: files\ngroup: sss\ngroup: files\n",
        "passwd: files\ngroup: files\ngroup: ldap\n",
        # Malformed relevant entries are unprovable.
        "passwd: files [NOTFOUND=return\ngroup: files\n",
        "passwd: files\ngroup: files\ninitgroups\n",
        "passwd: files\ngroup:\n",
        # glibc reads physical lines on LF only; VT and FF are whitespace inside a line.
        "passwd: files\ngroup: files\vsss\n",
        "passwd: files\ngroup: files\fsss\n",
        # Brackets are an action grammar, not a comment.
        "passwd: files [BROKEN]\ngroup: files\n",
        "passwd: files [NOTFOUND=]\ngroup: files\n",
        "passwd: files [NOTFOUND return]\ngroup: files\n",
        "passwd: files [NOTFOUND=return\ngroup: files\n",
        "passwd: [NOTFOUND=return] files\ngroup: files\n",
        "PASSWD: sss\npasswd: files\ngroup: files\n",
    ],
    ids=[
        "sss",
        "ldap",
        "compat",
        "winbind",
        "remote-initgroups",
        "no-group-line",
        "empty",
        "colon-less-initgroups",
        "colon-less-override",
        "colon-less-passwd",
        "duplicate-first-remote",
        "duplicate-last-remote",
        "unterminated-action",
        "bare-name",
        "empty-service-list",
        "vertical-tab",
        "form-feed",
        "unknown-action",
        "action-without-value",
        "action-without-equals",
        "unclosed-action",
        "action-before-service",
        "case-variant",
    ],
)
def test_directory_service_or_unknown_sources_are_shared(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, nss: str
) -> None:
    _tree(monkeypatch, tmp_path, nss=nss)
    assert foreign_write.foreign_write(_facts(0o100664)) == "group"


def test_without_nsswitch_conf_group_write_is_shared(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # macOS has no nsswitch.conf; Open Directory may consult network directories.
    _tree(monkeypatch, tmp_path, nss=None)
    assert foreign_write.foreign_write(_facts(0o100664)) == "group"
    assert foreign_write.foreign_write(_facts(0o100644)) is None


@pytest.mark.parametrize(
    "services, drop_in",
    [
        (("io.systemd.DynamicUser", "io.systemd.Home"), None),
        (("io.systemd.DynamicUser",), "bob:alice.membership"),
        (("io.systemd.DynamicUser",), "carol.user"),
    ],
    ids=["homed", "membership-drop-in", "user-drop-in"],
)
def test_userdb_beyond_dynamic_users_is_shared(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    services: tuple[str, ...],
    drop_in: str | None,
) -> None:
    _tree(monkeypatch, tmp_path, userdb_services=services, drop_in=drop_in)
    assert foreign_write.foreign_write(_facts(0o100664)) == "group"


@pytest.mark.parametrize(
    "passwd, group",
    [
        (PASSWD, "alice:x:1001:bob\n"),  # supplementary member
        (PASSWD + "carol:x:1003:1001::/home/carol:/bin/sh\n", GROUP),  # foreign primary
        ("alice:x:1001:1001::/h:/bin/sh\n", "users:x:1001:\n"),  # shared name (users, staff)
        (PASSWD, GROUP + "other:x:1001:\n"),  # duplicate gid
        (PASSWD + "+@netgroup::::::\n", GROUP),  # NIS compat import
        (PASSWD, GROUP + "+\n"),
        ("alice:x:1001:1000::/h:/bin/sh\n", "alice:x:1001:\n"),  # not alice's primary
        ("bob:x:1002:1002::/h:/bin/sh\n", "alice:x:1001:\n"),  # owner unknown
        (PASSWD, "bob:x:1002:\n"),  # group unknown
    ],
    ids=[
        "supplementary-member",
        "foreign-primary",
        "shared-name",
        "duplicate-gid",
        "compat-passwd",
        "compat-group",
        "not-primary",
        "unknown-owner",
        "unknown-group",
    ],
)
def test_shared_or_unprovable_groups_are_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, passwd: str, group: str
) -> None:
    _tree(monkeypatch, tmp_path, passwd=passwd, group=group)
    assert foreign_write.foreign_write(_facts(0o100664)) == "group"


@pytest.mark.parametrize(
    "gshadow, shared",
    [
        ("alice:!::\n", False),
        ("alice:!*::alice\n", False),
        ("alice:!::bob\n", True),
        ("alice:!:bob:\n", True),
        ("alice:$6$secret::\n", True),
    ],
    ids=["locked", "owner-member", "member", "admin", "group-password"],
)
def test_readable_gshadow_is_honoured(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, gshadow: str, shared: bool
) -> None:
    _tree(monkeypatch, tmp_path, gshadow=gshadow)
    assert (foreign_write.foreign_write(_facts(0o100664)) == "group") is shared


def test_dynamic_service_user_range_is_never_private(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _tree(
        monkeypatch,
        tmp_path,
        passwd="svc:x:61200:61200::/:/usr/sbin/nologin\n",
        group="svc:x:61200:\n",
    )
    assert foreign_write.foreign_write(_facts(0o100664, uid=61200, gid=61200)) == "group"


def test_a_group_gaining_a_member_is_noticed_after_the_cache_expires(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _tree(monkeypatch, tmp_path)
    now = [100.0]
    monkeypatch.setattr(foreign_write.time, "monotonic", lambda: now[0])
    assert foreign_write.foreign_write(_facts(0o100664)) is None
    (root / "etc/group").write_text("alice:x:1001:bob\nbob:x:1002:\n")
    now[0] += foreign_write._TTL_SECONDS  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    assert foreign_write.foreign_write(_facts(0o100664)) == "group"


def test_real_account_files_decide_for_the_current_user(tmp_path: Path) -> None:
    # No fakes: a file this account creates with g+w is accepted exactly when the local files
    # prove its group is this account's alone.
    path = tmp_path / "f"
    path.write_text("x")
    path.chmod(0o664)
    facts = path.stat()
    expected = foreign_write._lookup_private_group(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        facts.st_uid, facts.st_gid
    )
    assert foreign_write.writable_by_others(facts) is not expected
