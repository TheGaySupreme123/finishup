"""The TUI upgrade handoff names the launcher the install has on PATH (ADR-048).

A transitional ``yoetz`` distribution links only ``yoetz``; telling its user to re-run
``finishup`` sends them to a command that does not exist.
"""

from __future__ import annotations

from collections.abc import Sequence

import pytest

from finishup.application.package_update import PackageUpdateAdvisory, upgrade_command_for
from finishup.tui.app import FinishUpTui, relaunch_command
from finishup.tui.symbols import Level
from finishup.tui.widgets.views import BaseView


def test_the_relaunch_command_follows_the_installed_distribution() -> None:
    assert relaunch_command("yoetz") == "yoetz"
    assert relaunch_command("finishup") == "finishup"


class _Runtime:
    def __init__(self, advisory: PackageUpdateAdvisory) -> None:
        self._advisory = advisory

    async def package_update_advisory(self, *, allow_network: bool) -> PackageUpdateAdvisory:
        assert allow_network is True
        return self._advisory

    def project_root(self) -> str:
        return "/srv/finishup"


@pytest.mark.anyio
@pytest.mark.parametrize(("package", "launcher"), [("yoetz", "yoetz"), ("finishup", "finishup")])
async def test_choosing_upgrade_says_which_command_to_re_run(package: str, launcher: str) -> None:
    advisory = PackageUpdateAdvisory(
        outcome="newer_available",
        installed_version="0.3.0",
        latest_version="0.4.0",
        is_newer=True,
        upgrade_command=upgrade_command_for(package=package),
        source="network",
        package=package,
    )
    app = FinishUpTui(_Runtime(advisory))  # pyright: ignore[reportArgumentType]
    said: list[tuple[str, tuple[str, ...]]] = []

    def say(level: Level, title: str, body: Sequence[str] = (), *, details: object = ()) -> None:
        del level, details
        said.append((title, tuple(body)))

    async def ask(view: BaseView) -> str:
        del view
        return "upgrade"

    app.say = say  # pyright: ignore[reportAttributeAccessIssue]
    app.ask = ask  # pyright: ignore[reportAttributeAccessIssue]

    assert await app._offer_package_upgrade_if_newer() is False  # pyright: ignore[reportPrivateUsage]

    assert said[0][0] == f"Upgrade the package, then re-run {launcher}"
    assert f"Command: {upgrade_command_for(package=package)}" in said[0][1]
