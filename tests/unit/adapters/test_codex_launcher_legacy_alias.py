"""Installed-script proof for the deprecated ``yoetz`` alias (ADR-048).

The alias is declared by the transitional ``yoetz`` distribution, so only that distribution's
RECORD can prove it; the ``finishup`` RECORD never vouches for a script it did not install.
"""

from __future__ import annotations

import base64
import hashlib
import tempfile
from collections.abc import Iterator
from importlib.metadata import FileHash, PackageNotFoundError, PackagePath
from pathlib import Path

import pytest

from finishup.adapters.integrations.codex_launcher import installed_launcher


@pytest.fixture
def scripts(
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[tuple[Path, dict[str, list[str]], list[str]]]:
    # The launcher gate refuses shared/writable ancestors, including /tmp.
    with tempfile.TemporaryDirectory(prefix=".yz-alias-", dir=Path.home()) as raw_root:
        root = Path(raw_root)
        owned: dict[str, list[str]] = {}
        requested: list[str] = []

        recorded: dict[str, bytes] = {}

        class Package:
            def __init__(self, names: list[str]) -> None:
                self.files: list[PackagePath] = []
                for name in names:
                    # RECORD holds the bytes as installed, not whatever the file holds now.
                    data = recorded[name]
                    record = PackagePath(name)
                    digest = hashlib.sha256(data).digest()
                    record.hash = FileHash(
                        "sha256=" + base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
                    )
                    record.size = len(data)
                    self.files.append(record)

            def locate_file(self, path: PackagePath) -> Path:
                return root / path

        def scripts_path(_name: str) -> str:
            return str(root)

        def distribution(name: str) -> Package:
            requested.append(name)
            if name not in owned:
                raise PackageNotFoundError(name)
            return Package(owned[name])

        monkeypatch.setattr(
            "finishup.adapters.integrations.codex_launcher.distribution", distribution
        )
        monkeypatch.setattr(
            "finishup.adapters.integrations.codex_launcher.sysconfig.get_path",
            scripts_path,
        )
        monkeypatch.setattr(
            "finishup.adapters.integrations.codex_launcher.read_runtime_pin", lambda: None
        )
        for name in ("finishup", "yoetz"):
            script = root / name
            recorded[name] = f"#!/test/python\n# {name}\n".encode()
            script.write_bytes(recorded[name])
            script.chmod(0o700)
        yield root, owned, requested


def test_finishup_script_is_proven_by_the_finishup_record(
    scripts: tuple[Path, dict[str, list[str]], list[str]],
) -> None:
    root, owned, requested = scripts
    owned["finishup"] = ["finishup"]

    proof = installed_launcher()

    assert proof is not None and proof[0] == str(root / "finishup")
    assert requested == ["finishup"]


def test_alias_is_proven_only_by_the_transitional_record(
    scripts: tuple[Path, dict[str, list[str]], list[str]],
) -> None:
    root, owned, requested = scripts
    owned["yoetz"] = ["yoetz"]

    proof = installed_launcher("yoetz")

    assert proof is not None and proof[0] == str(root / "yoetz")
    assert proof[1] == "sha256:" + hashlib.sha256((root / "yoetz").read_bytes()).hexdigest()
    assert requested == ["yoetz"]


def test_the_finishup_record_never_vouches_for_the_alias(
    scripts: tuple[Path, dict[str, list[str]], list[str]],
) -> None:
    _root, owned, _requested = scripts
    owned["finishup"] = ["finishup", "yoetz"]

    assert installed_launcher("yoetz") is None


def test_a_modified_alias_script_is_not_owned(
    scripts: tuple[Path, dict[str, list[str]], list[str]],
) -> None:
    root, owned, _requested = scripts
    owned["yoetz"] = ["yoetz"]
    (root / "yoetz").write_bytes(b"#!/test/python\n# changed!\n")

    assert installed_launcher("yoetz") is None


def test_unknown_script_names_are_refused_before_any_lookup(
    scripts: tuple[Path, dict[str, list[str]], list[str]],
) -> None:
    _root, _owned, requested = scripts

    assert installed_launcher("python") is None
    assert requested == []
