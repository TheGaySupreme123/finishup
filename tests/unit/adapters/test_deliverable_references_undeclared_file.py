"""tb4n2 R2: a declared deliverable that loads a created, undeclared file (ADR-035 amendment)."""

from __future__ import annotations

import asyncio
import os
import subprocess
from pathlib import Path

import pytest

from builders.observed_runs import ObservedLedger
from yoetz.adapters.git_change_capture import GitChangeCaptureAdapter
from yoetz.application.check_change import (
    count_undeclared_references,
    requested_output_states,
)
from yoetz.domain.events import (
    EventSchema,
    ObligationPublishedPayload,
    ObligationStatus,
    PlanPublishedPayload,
    RequestedItem,
    RequestedItemKind,
    RequestedItemRole,
)
from yoetz.domain.values import obligation_id
from yoetz.kernel.projections import ProjectionState
from yoetz.kernel.reducers import replay
from yoetz.ports.change_capture import CheckWorkspaceSource

_OBLIGATION = obligation_id("obl_00000000-0000-4000-8000-000000000001")
_REQUEST = "req_00000000-0000-4000-8000-000000000001"
_GIT_ENV = {
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
    "LANG": "C",
    "LC_ALL": "C",
    "PATH": os.defpath,
}
_CRACKER = (
    "import numpy as np\nMODEL = np.load('english_model.npz')\ndef crack(text):\n    return text\n"
)


@pytest.fixture(autouse=True)
def isolated_global_git(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    monkeypatch.setenv("HOME", os.fspath(home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)


def _git(repository: Path, *arguments: str) -> None:
    subprocess.run(
        ("git", *arguments),
        cwd=repository,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=True,
        env={**_GIT_ENV, "HOME": os.fspath(repository)},
    )


def _repository(tmp_path: Path, files: dict[str, str]) -> tuple[Path, object]:
    repository = tmp_path / "app"
    repository.mkdir(mode=0o700)
    _git(repository, "init", "--quiet")
    for name, text in files.items():
        (repository / name).write_text(text, encoding="utf-8")
    _git(repository, "add", "--", *files)
    _git(
        repository,
        "-c",
        "user.name=Yoetz Test",
        "-c",
        "user.email=yoetz@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "baseline",
    )
    return repository, GitChangeCaptureAdapter().read_task_base(os.fspath(repository))


def _item(
    value: str,
    role: RequestedItemRole = RequestedItemRole.OUTPUT,
    kind: RequestedItemKind = RequestedItemKind.FILE,
) -> RequestedItem:
    return RequestedItem(kind, value, role=role)


def _projection(
    *items: RequestedItem, status: ObligationStatus = ObligationStatus.OPEN
) -> ProjectionState:
    ledger = ObservedLedger()
    ledger.append(
        EventSchema("obligation_published", "1.1.0"),
        ObligationPublishedPayload(
            obligation_id=_OBLIGATION,
            description="Deliver the cracker",
            evidence_expectation="The files",
            status=status,
            requested_items=items,
            acknowledged_not_done_reason=(
                "Out of scope." if status is ObligationStatus.ACKNOWLEDGED_NOT_DONE else None
            ),
        ),
        observed=False,
    )
    ledger.append(
        EventSchema("plan_published", "1.0.0"),
        PlanPublishedPayload(1, "Plan", (_OBLIGATION,)),
        observed=False,
    )
    return replay(ledger.prefix)


def _references(repository: Path, base: object, *items: RequestedItem) -> int:
    return _count(repository, base, _projection(*items))


def _count(repository: Path, base: object, projection: ProjectionState) -> int:
    adapter = GitChangeCaptureAdapter()
    capture = adapter.capture_metadata(os.fspath(repository), base)  # type: ignore[arg-type]
    source = CheckWorkspaceSource(os.fspath(repository), "hmac-sha256:" + "0" * 64)

    async def run() -> int:
        states = await requested_output_states(
            projection=projection,
            capture=capture,
            source=source,
            port=adapter,
            request_id=_REQUEST,
        )
        return await count_undeclared_references(
            projection=projection,
            capture=capture,
            source=source,
            port=adapter,
            states=states,
            blocked=None,
            request_id=_REQUEST,
        )

    return asyncio.run(run())


def _cracker(tmp_path: Path, text: str = _CRACKER) -> tuple[Path, object]:
    repository, base = _repository(tmp_path, {"README.md": "Cracker\n"})
    (repository / "cracker.py").write_text(text, encoding="utf-8")
    (repository / "english_model.npz").write_bytes(b"\x93NUMPY\x00\x01model")
    return repository, base


def test_interleaved_vigenere_deliverable_loading_an_undeclared_model_is_disclosed(
    tmp_path: Path,
) -> None:
    repository, base = _cracker(tmp_path)
    declared = os.fspath(repository / "cracker.py")

    assert _references(repository, base, _item(declared)) == 1
    # Declaring the model, as an output or as an input, clears the disclosure.
    assert _references(repository, base, _item(declared), _item("english_model.npz")) == 0
    assert (
        _references(
            repository,
            base,
            _item(declared),
            _item("english_model.npz", RequestedItemRole.INPUT),
        )
        == 0
    )


@pytest.mark.parametrize(
    "literal",
    [
        '"/app/english_model.npz"',
        "f'{HERE}/english_model.npz'",
        "`./english_model.npz`",
        '"english_model.npz"',
    ],
)
def test_absolute_suffix_and_basename_literals_match(tmp_path: Path, literal: str) -> None:
    repository, base = _cracker(tmp_path, f"MODEL = load({literal})\n")
    assert _references(repository, base, _item("cracker.py")) == 1


def test_a_model_inside_a_declared_directory_is_declared(tmp_path: Path) -> None:
    repository, base = _repository(tmp_path, {"README.md": "Cracker\n"})
    (repository / "models").mkdir()
    (repository / "models" / "english_model.npz").write_bytes(b"model")
    (repository / "cracker.py").write_text("load('models/english_model.npz')\n", "utf-8")

    assert _references(repository, base, _item("cracker.py")) == 1
    assert (
        _references(
            repository,
            base,
            _item("cracker.py"),
            _item("models", kind=RequestedItemKind.DIRECTORY),
        )
        == 0
    )


def test_a_reference_to_a_pre_existing_tracked_file_is_not_disclosed(tmp_path: Path) -> None:
    repository, base = _repository(tmp_path, {"english_model.npz": "tracked\n"})
    (repository / "cracker.py").write_text(_CRACKER, encoding="utf-8")
    (repository / "english_model.npz").write_text("tracked and edited\n", encoding="utf-8")

    assert _references(repository, base, _item("cracker.py")) == 0


def test_short_basenames_and_unreferenced_files_are_not_disclosed(tmp_path: Path) -> None:
    repository, base = _repository(tmp_path, {"README.md": "Cracker\n"})
    (repository / "cracker.py").write_text("x = load('m.np')\nprint('hello')\n", "utf-8")
    (repository / "data").mkdir()
    # A basename under five bytes is too common to count without its directory.
    (repository / "data" / "m.np").write_bytes(b"m")
    (repository / "notes.txt").write_text("scratch\n", encoding="utf-8")

    assert _references(repository, base, _item("cracker.py")) == 0


def test_non_source_binary_and_credential_named_deliverables_are_never_read(
    tmp_path: Path,
) -> None:
    repository, base = _cracker(tmp_path)
    # A text deliverable that is not source code.
    (repository / "report.txt").write_text("see english_model.npz\n'english_model.npz'\n", "utf-8")
    # A binary deliverable with a matching literal after a NUL byte.
    (repository / "tool.py").write_bytes(b"\x00\x01'english_model.npz'\n")
    # A credential-named deliverable is never opened.
    (repository / ".env").write_text("MODEL='english_model.npz'\n", encoding="utf-8")

    assert (
        _references(
            repository,
            base,
            _item("report.txt"),
            _item("tool.py"),
            _item(".env"),
            _item("cracker.py", RequestedItemRole.INPUT),
        )
        == 0
    )


def test_suffix_less_deliverable_needs_a_shebang(tmp_path: Path) -> None:
    repository, base = _cracker(tmp_path)
    (repository / "crack").write_text(
        "#!/usr/bin/env python3\nload('english_model.npz')\n", "utf-8"
    )
    (repository / "notes").write_text("load('english_model.npz')\n", encoding="utf-8")

    assert _references(repository, base, _item("crack")) == 1
    assert _references(repository, base, _item("notes")) == 0


def test_a_linked_deliverable_is_not_followed(tmp_path: Path) -> None:
    repository, base = _cracker(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "real.py").write_text(_CRACKER, encoding="utf-8")
    (repository / "linked.py").symlink_to(outside / "real.py")
    (repository / "lib").symlink_to(outside, target_is_directory=True)

    assert _references(repository, base, _item("linked.py")) == 0
    assert _references(repository, base, _item("lib/real.py")) == 0


def test_acknowledged_not_done_obligation_is_skipped(tmp_path: Path) -> None:
    repository, base = _cracker(tmp_path)
    projection = _projection(_item("cracker.py"), status=ObligationStatus.ACKNOWLEDGED_NOT_DONE)
    assert _count(repository, base, projection) == 0


def test_adapter_returns_a_count_only_and_refuses_unsafe_paths(tmp_path: Path) -> None:
    from yoetz.ports.change_capture import ChangeCaptureUnavailable

    repository, _base = _cracker(tmp_path)
    adapter = GitChangeCaptureAdapter()
    workspace = os.fspath(repository)
    found = adapter.count_undeclared_references(
        workspace, ("cracker.py", "README.md"), ("english_model.npz",)
    )
    assert found == 1 and type(found) is int
    assert adapter.count_undeclared_references(workspace, ("cracker.py",), ()) == 0
    for unsafe in ("../cracker.py", "/etc/passwd", "a/./b"):
        with pytest.raises(ChangeCaptureUnavailable):
            adapter.count_undeclared_references(workspace, (unsafe,), ("english_model.npz",))
    with pytest.raises(ChangeCaptureUnavailable):
        adapter.count_undeclared_references(workspace, ("x.py",) * 17, ("english_model.npz",))


def test_only_the_first_bounded_prefix_is_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import yoetz.adapters.git_change_capture as capture_module

    repository, _base = _cracker(tmp_path, "#" * 64 + "\nload('english_model.npz')\n")
    adapter = GitChangeCaptureAdapter()
    workspace = os.fspath(repository)
    assert adapter.count_undeclared_references(workspace, ("cracker.py",), ("english_model.npz",))
    monkeypatch.setattr(capture_module, "_MAX_REFERENCE_FILE_BYTES", 32)
    assert not adapter.count_undeclared_references(
        workspace, ("cracker.py",), ("english_model.npz",)
    )


def test_a_failing_read_is_not_raised(tmp_path: Path) -> None:
    repository, base = _cracker(tmp_path)
    adapter = GitChangeCaptureAdapter()
    capture = adapter.capture_metadata(os.fspath(repository), base)  # type: ignore[arg-type]
    projection = _projection(_item("cracker.py"))
    source = CheckWorkspaceSource(os.fspath(repository), "hmac-sha256:" + "0" * 64)

    class Broken:
        def probe_requested_paths(self, workspace: str, values: tuple[str, ...]) -> object:
            return adapter.probe_requested_paths(workspace, values)

        def count_undeclared_references(self, *_arguments: object) -> int:
            raise RuntimeError("boom")

    async def run() -> int:
        states = await requested_output_states(
            projection=projection,
            capture=capture,
            source=source,
            port=adapter,
            request_id=_REQUEST,
        )
        return await count_undeclared_references(
            projection=projection,
            capture=capture,
            source=source,
            port=Broken(),
            states=states,
            blocked=None,
            request_id=_REQUEST,
        )

    assert asyncio.run(run()) == 0
