"""An install on an unadvertised cell says so instead of passing as certified (issue #724)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

import finishup.version as version_module
from finishup.version import (
    PLATFORM_CELL_UNTESTED,
    build_version_manifest,
    platform_cell,
    version_manifest_json,
)


@pytest.mark.parametrize(
    ("os_name", "machine", "cell"),
    [
        ("Darwin", "arm64", "macosx_11_0_arm64"),
        ("Linux", "x86_64", "manylinux_2_28_x86_64"),
        ("Linux", "amd64", "manylinux_2_28_x86_64"),
    ],
)
def test_advertised_cells_are_certified(os_name: str, machine: str, cell: str) -> None:
    result = platform_cell(
        os_name=os_name,
        machine=machine,
        libc=("glibc", "2.28"),
        python=(3, 14, 6),
        implementation="CPython",
    )

    assert result.certified is True
    assert result.cell == cell
    assert result.as_json() == {
        "cell": cell,
        "certified": True,
        "certified_cells": ["macosx_11_0_arm64", "manylinux_2_28_x86_64"],
        "machine": machine,
        "os_name": os_name,
    }


@pytest.mark.parametrize(
    ("os_name", "machine"),
    [
        ("Linux", "aarch64"),  # WSL 2 on Windows-on-ARM, Graviton, Raspberry Pi, Asahi
        ("Darwin", "x86_64"),
        ("Linux", "riscv64"),
        ("Windows", "AMD64"),
    ],
)
def test_other_cells_are_untested_not_presumed_compatible(os_name: str, machine: str) -> None:
    result = platform_cell(
        os_name=os_name,
        machine=machine,
        libc=("glibc", "2.28"),
        python=(3, 14, 6),
        implementation="CPython",
    )

    assert result.certified is False
    assert result.cell is None


def test_manifest_flags_an_untested_cell_and_still_validates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(version_module.platform, "system", lambda: "Linux")
    monkeypatch.setattr(version_module.platform, "machine", lambda: "aarch64")

    manifest = build_version_manifest()
    document = json.loads(version_manifest_json(manifest))
    schema = json.loads(Path("schemas/version/version-manifest-2.3.0.schema.json").read_text())

    assert PLATFORM_CELL_UNTESTED in manifest.limitations
    assert manifest.limitations == tuple(sorted(set(manifest.limitations), key=str.encode))
    assert document["machine"] == "aarch64"
    assert PLATFORM_CELL_UNTESTED in document["limitations"]
    Draft202012Validator(schema).validate(document)  # pyright: ignore[reportUnknownMemberType]


def test_manifest_on_a_certified_cell_carries_no_platform_limitation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(version_module.platform, "system", lambda: "Linux")
    monkeypatch.setattr(version_module.platform, "machine", lambda: "x86_64")

    monkeypatch.setattr(version_module.platform, "libc_ver", lambda: ("glibc", "2.28"))
    # The older-python CI lane runs this too; certify whichever minor is running.
    monkeypatch.setattr(
        version_module,
        "_CERTIFIED_PYTHON",
        (version_module.platform.python_implementation(), tuple(sys.version_info[:3])),
    )

    assert PLATFORM_CELL_UNTESTED not in build_version_manifest().limitations


@pytest.mark.parametrize(
    "libc", [("musl", "1.2.5"), ("glibc", "2.27"), ("", ""), ("glibc", "invalid")]
)
def test_linux_libc_outside_certified_cell_stays_unproven(
    monkeypatch: pytest.MonkeyPatch, libc: tuple[str, str]
) -> None:
    monkeypatch.setattr(version_module.platform, "system", lambda: "Linux")
    monkeypatch.setattr(version_module.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(version_module.platform, "libc_ver", lambda: libc)

    assert platform_cell().certified is False
    assert platform_cell().cell is None
    assert PLATFORM_CELL_UNTESTED in build_version_manifest().limitations


@pytest.mark.parametrize(
    ("python", "implementation", "named"),
    [
        ((3, 12, 13), "CPython", "3.12.13"),
        ((3, 13, 4), "CPython", "3.13.4"),
        ((3, 14, 0), "CPython", "3.14.0"),
        ((3, 14, 7), "CPython", "3.14.7"),
        ((3, 14, 6), "PyPy", "PyPy 3.14.6"),
    ],
)
def test_any_interpreter_but_the_release_cell_is_untested(
    python: tuple[int, int, int], implementation: str, named: str
) -> None:
    # Issue #1119: requires-python admits these, but release evidence covers CPython 3.14.6 only.
    result = platform_cell(
        os_name="Darwin",
        machine="arm64",
        libc=("", ""),
        python=python,
        implementation=implementation,
    )

    assert result.certified is False
    assert result.cell is None
    assert result.python_version == named
    assert "python_version" not in result.as_json()


def test_release_cell_python_is_certified() -> None:
    result = platform_cell(
        os_name="Darwin",
        machine="arm64",
        libc=("", ""),
        python=(3, 14, 6),
        implementation="CPython",
    )

    assert result.certified is True
    assert result.python_version == "3.14.6"


@pytest.mark.parametrize("release", ["2.28", "2.28.1", "2.40", "3.0"])
def test_linux_glibc_at_or_above_floor_is_certified(release: str) -> None:
    assert platform_cell(
        os_name="Linux",
        machine="x86_64",
        libc=("glibc", release),
        python=(3, 14, 6),
        implementation="CPython",
    ).certified
