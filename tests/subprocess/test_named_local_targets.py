"""Two named local servers, each with its own service, and CLI calls that follow the selection.

ADR-051 (design section 5): ``finishup server add NAME --local`` makes an independent instance
root; ``finishup server use NAME`` writes the owner-only selection; every new client process then
resolves that root, so ``service start`` and ``service status`` reach that target's own service,
and switching the selection switches the service a fresh process reaches. Nothing here sets an
isolation-root variable: the selection alone decides (run with both root variables unset).

Services are stopped only through ``finishup server remove``, which signals the process stamped
in that target root's own singleton lock — never anything matched by name or pattern.
"""

from __future__ import annotations

import json
import os
import pwd
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import cast

import pytest

_TIMEOUT = 90


@pytest.fixture
def selection_environment() -> Iterator[dict[str, str]]:
    """The hermetic environment with a short owner-only config and state home.

    Target roots live beneath the ambient state directory and must keep their socket paths
    under ``sun_path``; the hermetic tree is too deep for that, so state and config move to a
    short private directory beneath the account's real home (outside shared temp).
    """

    real_home = Path(pwd.getpwuid(os.getuid()).pw_dir)
    base = Path(tempfile.mkdtemp(prefix=".yz-nlt-", dir=real_home))
    base.chmod(0o700)
    environment = {
        name: value
        for name, value in os.environ.items()
        if not name.startswith(("FINISHUP_", "YOETZ_"))
    }
    for variable, leaf in (("XDG_STATE_HOME", "s"), ("XDG_CONFIG_HOME", "c")):
        (base / leaf).mkdir(mode=0o700)
        environment[variable] = str(base / leaf)
    try:
        yield environment
    finally:
        shutil.rmtree(base, ignore_errors=True)


def _finishup(environment: dict[str, str], *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - this interpreter and fixed arguments
        (sys.executable, "-m", "finishup", *arguments),
        env=environment,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=_TIMEOUT,
        check=False,
    )


def _json(result: subprocess.CompletedProcess[str]) -> dict[str, object]:
    assert result.returncode == 0, result.stderr
    return cast(dict[str, object], json.loads(result.stdout))


def test_cli_calls_follow_the_selection_between_two_named_local_servers(
    selection_environment: dict[str, str],
) -> None:
    env = selection_environment
    names = ("work", "lab")
    try:
        for name in names:
            added = _finishup(env, "server", "add", name, "--local")
            assert added.returncode == 0, added.stderr

        assert _finishup(env, "server", "use", "work").returncode == 0
        work_started = _json(_finishup(env, "service", "start", "--json"))
        work_status = _json(_finishup(env, "service", "status", "--json"))
        assert work_status["service_instance_id"] == work_started["service_instance_id"]
        work_isolation = _json(_finishup(env, "service", "isolation", "--json"))
        assert (work_isolation["binding"], work_isolation["mode"]) == ("selection", "isolated")
        assert work_isolation["lifecycle"] == "persistent"

        assert _finishup(env, "server", "use", "lab").returncode == 0
        lab_started = _json(_finishup(env, "service", "start", "--json"))
        lab_status = _json(_finishup(env, "service", "status", "--json"))
        assert lab_status["service_instance_id"] == lab_started["service_instance_id"]
        assert lab_status["service_instance_id"] != work_status["service_instance_id"]
        lab_isolation = _json(_finishup(env, "service", "isolation", "--json"))
        assert (
            lab_isolation["path_identity"] != work_isolation["path_identity"]  # every root moved
        )

        # ``service start`` is idempotent: the running service is kept.
        again = _json(_finishup(env, "service", "start", "--json"))
        assert again["service_instance_id"] == lab_status["service_instance_id"]

        # ``server status NAME`` probes one target without changing the selection.
        work_probe = _json(_finishup(env, "server", "status", "work", "--json"))
        probe = cast(dict[str, object], work_probe["probe"])
        assert probe["service_instance_id"] == work_status["service_instance_id"]
        assert probe["outcome"] in {"ready", "reachable"}
        assert work_probe["source"] == "selection"
        current = _json(_finishup(env, "server", "status", "--json"))
        assert cast(dict[str, object], current["target"])["name"] == "lab"
        assert (
            cast(dict[str, object], current["probe"])["service_instance_id"]
            == lab_status["service_instance_id"]
        )

        # Back to the everyday server: a fresh process no longer reaches either target.
        assert _finishup(env, "server", "use", "local").returncode == 0
        everyday = _json(_finishup(env, "server", "status", "--json"))
        assert everyday["source"] == "ambient"
        assert cast(dict[str, object], everyday["probe"])["outcome"] == "not_running"
    finally:
        for name in names:
            _finishup(env, "server", "remove", name, "--select-local")
    listed = _finishup(env, "server", "list")
    assert listed.returncode == 0
    assert "work" not in listed.stdout and "lab" not in listed.stdout


@pytest.fixture
def hermetic_everyday_environment() -> Iterator[dict[str, str]]:
    """Every everyday folder (data, state, config, cache, runtime) in one short private tree.

    The everyday service is started here, so none of its folders may resolve to this account's
    real installation.
    """

    real_home = Path(pwd.getpwuid(os.getuid()).pw_dir)
    base = Path(tempfile.mkdtemp(prefix=".yz-amb-", dir=real_home))
    base.chmod(0o700)
    environment = {
        name: value
        for name, value in os.environ.items()
        if not name.startswith(("FINISHUP_", "YOETZ_"))
    }
    for variable, leaf in (
        ("XDG_STATE_HOME", "s"),
        ("XDG_CONFIG_HOME", "c"),
        ("XDG_DATA_HOME", "d"),
        ("XDG_CACHE_HOME", "k"),
        ("XDG_RUNTIME_DIR", "r"),
    ):
        (base / leaf).mkdir(mode=0o700)
        environment[variable] = str(base / leaf)
    try:
        yield environment
    finally:
        shutil.rmtree(base, ignore_errors=True)


def test_the_everyday_server_starts_in_its_own_root_while_another_is_selected(
    hermetic_everyday_environment: dict[str, str],
) -> None:
    """ADR-051: a spawned service serves its spawner's root, never the selection it did not use.

    With ``work`` selected, ``server connect local`` starts the everyday service; its spawn is
    told the everyday installation (``service run --ambient-root``), so the service binds the
    everyday endpoint and nothing starts in ``work``'s root.
    """

    env = hermetic_everyday_environment
    try:
        assert _finishup(env, "server", "add", "work", "--local").returncode == 0
        assert _finishup(env, "server", "use", "work").returncode == 0

        connected = _finishup(env, "server", "connect", "local")
        assert connected.returncode == 0, connected.stderr
        assert "this computer's everyday server" in connected.stdout

        everyday = _json(_finishup(env, "server", "status", "local", "--json"))
        everyday_probe = cast(dict[str, object], everyday["probe"])
        assert everyday_probe["outcome"] in {"ready", "reachable"}, everyday_probe
        assert everyday["source"] == "selection"  # the selection is untouched
        work = _json(_finishup(env, "server", "status", "work", "--json"))
        assert cast(dict[str, object], work["probe"])["outcome"] == "not_running"
    finally:
        # Stopped through its own control channel, never by pattern.
        _finishup(env, "server", "disconnect", "local")
        _finishup(env, "server", "remove", "work", "--select-local")
