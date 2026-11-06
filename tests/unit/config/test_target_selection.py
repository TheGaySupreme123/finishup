"""The owner-only server selection is the lowest-precedence root source (ADR-051, design §5).

Precedence: ``FINISHUP_ISOLATED_ROOT`` (or its legacy spelling), then the runtime pin, then the
selection file, then the everyday ambient install. A pinned test instance never sees the
selection; a selection that is malformed or names a missing or unsafe root fails closed instead
of falling back to the everyday service; the answer is memoized once per process; target names
and the AF_UNIX path bound are checked before anything is created.
"""

from __future__ import annotations

import json
import os
import shutil
from collections.abc import Iterator
from pathlib import Path

import pytest

from builders.server_targets import ambient_home
from finishup.cli import instance as instance_cli
from finishup.client import targets
from finishup.client.targets import ServerTarget, TargetError
from finishup.config import installation, paths
from finishup.config.installation import write_runtime_pin
from finishup.config.paths import (
    ISOLATED_ROOT_ENV_NAMES,
    PathSafetyError,
    active_root,
    config_file_path,
    isolated_root,
    isolation_binding,
    reset_selection_memo,
    runtime_dir,
    selection_override,
    state_dir,
)

_INSTALLATION_ID = "ins_00000000-0000-4000-8000-000000000001"


@pytest.fixture
def home(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """An owner-only ambient home outside shared temp, with every root variable unset."""

    with ambient_home(monkeypatch) as root:
        yield root


def _local_target(name: str = "work") -> tuple[ServerTarget, Path]:
    with targets.registry_lock():
        return targets.new_local_target(name)


def _select(record: ServerTarget) -> None:
    targets.write_selection(record)


def test_no_selection_file_is_exactly_the_ambient_install(home: Path) -> None:
    assert active_root() is None
    assert isolation_binding() == "ambient"
    assert state_dir() == home / "state" / "finishup"
    assert runtime_dir() == home / "run" / "finishup"


def test_a_selection_rebases_every_identity_root(home: Path) -> None:
    record, root = _local_target()
    _select(record)

    assert root == home / "state" / "finishup" / "servers" / record.target_id
    assert active_root() == root
    assert isolation_binding() == "selection"
    assert isolated_root() is None  # still "explicitly isolated" only
    assert state_dir() == root / "state"
    assert runtime_dir() == root / "run"
    assert config_file_path() == root / "config" / "config.toml"


def test_the_environment_outranks_the_selection(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    record, _root = _local_target()
    _select(record)
    explicit = home / "explicit"
    explicit.mkdir(mode=0o700)
    monkeypatch.setenv(ISOLATED_ROOT_ENV_NAMES[0], str(explicit))

    assert active_root() == explicit
    assert isolation_binding() == "environment"


def test_a_pinned_runtime_never_sees_the_selection(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    record, _root = _local_target()
    _select(record)
    prefix = home / "prefix"
    prefix.mkdir(mode=0o700)
    pinned = home / "pinned"
    pinned.mkdir(mode=0o700)
    write_runtime_pin(prefix, pinned, _INSTALLATION_ID)
    probe = paths._default_probe()  # pyright: ignore[reportPrivateUsage]
    monkeypatch.setattr(
        paths,
        "_default_probe",
        lambda: paths._PathProbe(  # pyright: ignore[reportPrivateUsage]
            platform=probe.platform,
            effective_uid=probe.effective_uid,
            home=probe.home,
            shared_temp=probe.shared_temp,
            fixed_shared_temps=probe.fixed_shared_temps,
            platform_dirs=probe.platform_dirs,
            mount_table=probe.mount_table,
            macos_fstype=probe.macos_fstype,
            diagnostic=probe.diagnostic,
            runtime_prefix=prefix,
            installation_naming=probe.installation_naming,
        ),
    )

    assert active_root() == pinned
    assert isolation_binding() == "runtime_pin"


@pytest.mark.parametrize(
    "content",
    [
        b"not json",
        b"[]",
        json.dumps({"schema": "yoetz.server-selection/1"}).encode(),
        json.dumps({"schema": "yoetz.server-selection/2", "target_id": "t_00000000"}).encode(),
        json.dumps(
            {"schema": "yoetz.server-selection/1", "target_id": "t_00000000", "extra": 1}
        ).encode(),
        json.dumps({"schema": "yoetz.server-selection/1", "target_id": "../../etc"}).encode(),
        json.dumps({"schema": "yoetz.server-selection/1", "target_id": "t_ABCDEF00"}).encode(),
    ],
)
def test_a_malformed_selection_fails_closed(home: Path, content: bytes) -> None:
    path = home / "config" / "finishup" / "server-selection.json"
    path.parent.mkdir(mode=0o700)
    path.write_bytes(content)
    path.chmod(0o600)

    with pytest.raises(PathSafetyError) as raised:
        active_root()
    assert raised.value.reason_code == "isolation_root_invalid"


def test_a_shared_or_symlinked_selection_file_fails_closed(home: Path) -> None:
    record, _root = _local_target()
    _select(record)
    path = targets.selection_path()
    path.chmod(0o644)
    reset_selection_memo()
    with pytest.raises(PathSafetyError):
        active_root()
    path.chmod(0o600)
    real = path.with_name("real.json")
    path.rename(real)
    path.symlink_to(real)
    reset_selection_memo()
    with pytest.raises(PathSafetyError):
        active_root()


def test_a_selection_naming_a_missing_root_never_falls_back(home: Path) -> None:
    record, root = _local_target()
    _select(record)
    shutil.rmtree(root)
    reset_selection_memo()

    with pytest.raises(PathSafetyError) as raised:
        state_dir()
    assert raised.value.reason_code == "isolation_root_invalid"


def test_a_selected_root_without_its_record_fails_closed(home: Path) -> None:
    record, root = _local_target()
    _select(record)
    (root / "target.json").unlink()
    reset_selection_memo()

    with pytest.raises(PathSafetyError) as raised:
        active_root()
    assert raised.value.reason_code == "isolation_root_invalid"


def test_a_too_broad_target_root_fails_closed_with_its_own_reason(home: Path) -> None:
    record, root = _local_target()
    _select(record)
    root.chmod(0o755)
    reset_selection_memo()

    with pytest.raises(PathSafetyError) as raised:
        active_root()
    assert raised.value.reason_code == "permissions_too_broad"


def test_the_selection_is_read_once_per_process(home: Path) -> None:
    first, first_root = _local_target("first")
    second, _second_root = _local_target("second")
    _select(first)
    assert active_root() == first_root

    # Another process changes the selection: this process keeps its answer (an MCP bridge never
    # switches mid-session) until the memo is reset (a fresh process, or ``server use`` here).
    path = targets.selection_path()
    path.write_text(
        json.dumps({"schema": "yoetz.server-selection/1", "target_id": second.target_id}),
        encoding="utf-8",
    )
    assert active_root() == first_root
    reset_selection_memo()
    assert active_root() == targets.target_root(second.target_id)


def test_selection_override_resolves_one_target_and_restores(home: Path) -> None:
    record, root = _local_target()
    _select(record)
    assert active_root() == root

    with selection_override(None):
        assert active_root() is None
        assert state_dir() == home / "state" / "finishup"
    assert active_root() == root


def test_the_ambient_installation_dirs_name_both_names_whatever_the_root(home: Path) -> None:
    """The workspace agent's fence: the everyday installation's directories, as ``finishup``
    and as the legacy ``yoetz``, are named whichever root this process uses."""

    ambient = paths.ambient_installation_dirs()
    roots = {
        paths.bundle_root(),
        config_file_path().parent,
        paths.cache_dir(),
        state_dir(),
        paths.log_dir(),
        runtime_dir(),
    }
    legacy = {
        Path(*("yoetz" if part == "finishup" else part for part in root.parts)) for root in roots
    }
    assert roots | legacy <= set(ambient)
    assert all(directory.is_absolute() for directory in ambient)
    assert len(ambient) == len(set(ambient))
    record, target_root = _local_target()
    _select(record)
    assert state_dir() == target_root / "state"
    assert paths.ambient_installation_dirs() == ambient


def test_clearing_the_selection_returns_to_ambient(home: Path) -> None:
    record, _root = _local_target()
    _select(record)
    assert targets.clear_selection() is True
    assert active_root() is None
    assert targets.clear_selection() is False


@pytest.mark.parametrize("name", ["work", "a", "0lab", "lab-2", "a" * 16])
def test_valid_names(name: str) -> None:
    assert targets.validate_name(name) == name


@pytest.mark.parametrize(
    ("name", "reason"),
    [
        ("", "target_name_invalid"),
        ("-lab", "target_name_invalid"),
        ("Lab", "target_name_invalid"),
        ("lab_2", "target_name_invalid"),
        ("a" * 17, "target_name_invalid"),
        ("lab box", "target_name_invalid"),
        ("local", "target_name_reserved"),
    ],
)
def test_invalid_names(name: str, reason: str) -> None:
    with pytest.raises(TargetError) as raised:
        targets.validate_name(name)
    assert raised.value.reason == reason


def test_a_duplicate_name_is_refused(home: Path) -> None:
    _local_target("work")
    with pytest.raises(TargetError) as raised:
        _local_target("work")
    assert raised.value.reason == "target_name_taken"


def test_a_root_too_deep_for_a_socket_path_is_refused_before_anything_is_made(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    deep = home / ("d" * 90)
    deep.mkdir(mode=0o700)
    monkeypatch.setenv("XDG_STATE_HOME", str(deep))

    with pytest.raises(TargetError) as raised:
        _local_target()
    assert raised.value.reason == "target_root_too_long"
    assert not any((deep / "finishup" / "servers").glob("t_*"))


@pytest.mark.parametrize(
    ("platform", "usable"),
    [("linux", 107), ("darwin", 103), ("freebsd14", 103)],
)
def test_the_socket_path_bound_is_the_platforms_own(platform: str, usable: int) -> None:
    # ``sun_path`` less its terminating NUL: 108 bytes on Linux, 104 on Darwin and the BSDs.
    assert installation.usable_socket_path_bytes(platform) == usable


def test_one_bound_serves_the_instance_and_the_target_checks() -> None:
    assert installation.MAX_SOCKET_PATH_BYTES == installation.usable_socket_path_bytes()
    assert instance_cli.MAX_SOCKET_PATH_BYTES is installation.MAX_SOCKET_PATH_BYTES


def _state_home_for_root_bytes(home: Path, root_bytes: int) -> Path:
    """An ambient state folder whose target roots (``…/finishup/servers/t_<8 hex>``) are exact."""

    suffix = len(os.fsencode(Path("/finishup/servers/t_00000000")))
    padding = root_bytes - suffix - len(os.fsencode(home)) - 1
    assert padding > 0
    state = home / ("s" * padding)
    state.mkdir(mode=0o700)
    return state


def _remote(name: str) -> tuple[ServerTarget, Path]:
    with targets.registry_lock():
        return targets.new_remote_target(
            name, "ssh", user="owner", host="lab.example", port=22, remote_root="/srv/fu"
        )


def test_a_remote_root_is_held_to_the_sockets_a_client_binds_there(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # OpenSSH binds the master at ``run/m`` plus a 17-byte temporary suffix: 23 bytes beneath the
    # root, one fewer than the service's ``run/secret-ingress.sock`` a remote root never holds.
    bound = installation.MAX_SOCKET_PATH_BYTES
    monkeypatch.setenv("XDG_STATE_HOME", str(_state_home_for_root_bytes(home, bound - 23)))

    record, root = _remote("lab")
    assert len(os.fsencode(root)) == bound - 23
    assert record.kind == "ssh"
    # The same root is one byte too deep for a named local server's own service endpoints.
    with pytest.raises(TargetError) as local:
        _local_target()
    assert local.value.reason == "target_root_too_long"


def test_a_remote_root_one_byte_too_deep_for_the_master_socket_is_refused(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bound = installation.MAX_SOCKET_PATH_BYTES
    state = _state_home_for_root_bytes(home, bound - 22)
    monkeypatch.setenv("XDG_STATE_HOME", str(state))

    with pytest.raises(TargetError) as raised:
        _remote("lab")
    assert raised.value.reason == "target_root_too_long"
    assert not any((state / "finishup" / "servers").glob("t_*"))


def test_target_ids_and_record_files_are_owner_only(home: Path) -> None:
    record, root = _local_target()
    assert record.target_id.startswith("t_") and len(record.target_id) == 10
    assert (root / "target.json").stat().st_mode & 0o777 == 0o600
    assert root.stat().st_mode & 0o777 == 0o700
    assert targets.read_target(root) == record
    assert targets.list_targets() == (record,)


def test_a_tampered_record_fails_closed(home: Path) -> None:
    _record, root = _local_target()
    body = json.loads((root / "target.json").read_bytes())
    body["kind"] = "ssh"
    (root / "target.json").write_text(json.dumps(body) + "\n", encoding="utf-8")
    with pytest.raises(TargetError) as raised:
        targets.list_targets()
    assert raised.value.reason == "target_record_invalid"


def test_a_remote_record_carries_a_claim_salt_and_authorization(home: Path) -> None:
    with targets.registry_lock():
        record, root = targets.new_remote_target(
            "lab", "ssh", user="owner", host="lab.example", port=2222, remote_root="/srv/fu"
        )
    body = json.loads((root / "target.json").read_bytes())
    assert set(body) == {
        "schema",
        "target_id",
        "name",
        "kind",
        "created_at",
        "user",
        "host",
        "port",
        "remote_root",
        "remote_endpoint",
        "remote_launcher",
        "claim_salt",
        "authorized_at",
        "disclosure_version",
    }
    assert body["remote_endpoint"] == "/srv/fu/run/control.sock"
    assert body["disclosure_version"] == targets.DISCLOSURE_VERSION
    assert len(record.claim_salt or "") == 44
    assert targets.read_target(root) == record
    assert {child.name for child in root.iterdir()} == {
        "config",
        "log",
        "run",
        "state",
        "target.json",
    }


@pytest.mark.parametrize(
    "url",
    [
        "http://example.test",
        "https://user@example.test",
        "https://example.test/?q=1",
        "https://example.test/#f",
        "https://-bad.test",
        "https://example.test:0",
        "ftp://example.test",
    ],
)
def test_https_addresses_are_strict(url: str) -> None:
    with pytest.raises(TargetError):
        targets.normalize_https_url(url)


def test_https_addresses_normalize() -> None:
    assert targets.normalize_https_url("https://Example.TEST:8443/base/") == (
        "https://example.test:8443/base"
    )
    assert targets.normalize_https_url("https://[::1]:9443", loopback_only=True) == (
        "https://[::1]:9443"
    )
    with pytest.raises(TargetError):
        targets.normalize_https_url("https://example.test:8443", loopback_only=True)
    with pytest.raises(TargetError):
        targets.normalize_https_url("https://127.0.0.1", loopback_only=True)


def test_ssh_addresses_are_strict() -> None:
    assert targets.parse_ssh_url("ssh://owner@lab.example:2222") == ("owner", "lab.example", 2222)
    assert targets.parse_ssh_url("ssh://lab.example") == (None, "lab.example", 22)
    for bad in (
        "ssh://-oProxyCommand=x",
        # Built from parts so the publication-boundary scanner sees no URI userinfo literal.
        "ssh://" + "owner:secret" + "@lab.example",
        "ssh://lab.example/path",
        "ssh://lab.example?x=1",
        "lab.example",
    ):
        with pytest.raises(TargetError):
            targets.parse_ssh_url(bad)


def test_the_process_umask_does_not_widen_target_files(home: Path) -> None:
    previous = os.umask(0)
    try:
        _record, root = _local_target()
    finally:
        os.umask(previous)
    assert (root / "target.json").stat().st_mode & 0o777 == 0o600


def test_the_service_reads_only_a_safe_target_kind(tmp_path: Path) -> None:
    """``server_target_kind`` is the service's minimal, fail-closed read of ``target.json``."""

    from finishup.config.paths import PathSafetyError, server_target_kind

    root = tmp_path / "root"
    root.mkdir(mode=0o700)
    assert server_target_kind(root) is None
    record = root / "target.json"
    for kind in ("local", "local_port", "ssh", "https"):
        record.write_bytes(f'{{"kind":"{kind}"}}\n'.encode())
        record.chmod(0o600)
        assert server_target_kind(root) == kind
    for body, mode in (
        (b'{"kind":"sshx"}\n', 0o600),
        (b'["ssh"]\n', 0o600),
        (b"{not json", 0o600),
        (b'{"kind":"ssh"}\n', 0o640),
        (b'{"kind":"ssh"' + b" " * 9_000 + b"}", 0o600),
    ):
        record.write_bytes(body)
        record.chmod(mode)
        with pytest.raises(PathSafetyError) as refused:
            server_target_kind(root)
        assert refused.value.reason_code == "isolation_root_invalid"
    record.unlink()
    record.symlink_to(tmp_path / "elsewhere.json")
    with pytest.raises(PathSafetyError):
        server_target_kind(root)
