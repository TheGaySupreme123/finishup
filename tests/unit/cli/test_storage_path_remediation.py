"""A refused state path tells a WSL user where state may live (issue #723)."""

from __future__ import annotations

from finishup.cli.exits import remediation_message
from finishup.cli.instance import instance_failure_line
from finishup.config.paths import PathSafetyError


def test_network_filesystem_refusal_names_wsl_and_the_linux_disk() -> None:
    line = instance_failure_line(PathSafetyError("path_on_network_filesystem"))

    assert line.startswith("path_on_network_filesystem: ")
    assert "WSL" in line
    assert "/mnt/" in line
    assert "9p" in line and "drvfs" in line and "virtiofs" in line
    assert "FINISHUP_ISOLATED_ROOT" in line
    assert remediation_message("path_on_network_filesystem") is not None
