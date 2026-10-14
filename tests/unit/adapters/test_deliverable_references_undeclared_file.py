"""tb4n2 R2 / tb4n4: a declared deliverable that loads a created, undeclared file (ADR-035 amendment).

Since tb4n4 (#1044) the read returns which delivered file names which undeclared file, so the
receipt and the Stop gate can name it; ``_references`` counts the pairs it found.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import asyncio
import os
import subprocess
import tracemalloc
import zipfile
from pathlib import Path

import pytest

from builders.observed_runs import ObservedLedger
from finishup.adapters.git_change_capture import (
    _MAX_CLASSIFIED_OCCURRENCES,
    GitChangeCaptureAdapter,
    _dependencies,
)
from finishup.application.check_change import (
    requested_output_states,
    undeclared_references,
)
from finishup.domain.events import (
    EventSchema,
    ObligationPublishedPayload,
    ObligationStatus,
    PlanPublishedPayload,
    RequestedItem,
    RequestedItemKind,
    RequestedItemRole,
)
from finishup.domain.values import obligation_id
from finishup.kernel.projections import ProjectionState
from finishup.kernel.reducers import replay
from finishup.ports.change_capture import CheckWorkspaceSource

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
        "user.name=FinishUP Test",
        "-c",
        "user.email=finishup@example.invalid",
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
    return len(_pairs(repository, base, projection))


def _pairs(
    repository: Path, base: object, projection: ProjectionState
) -> tuple[tuple[str, str], ...]:
    adapter = GitChangeCaptureAdapter()
    capture = adapter.capture_metadata(os.fspath(repository), base)  # type: ignore[arg-type]
    source = CheckWorkspaceSource(os.fspath(repository), "hmac-sha256:" + "0" * 64)

    async def run() -> tuple[tuple[str, str], ...]:
        states = await requested_output_states(
            projection=projection,
            capture=capture,
            source=source,
            port=adapter,
            request_id=_REQUEST,
        )
        read = await undeclared_references(
            projection=projection,
            capture=capture,
            source=source,
            port=adapter,
            states=states,
            blocked=None,
            request_id=_REQUEST,
        )
        return read.pairs

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


# tb4n4 interleaved-vigenere S (#1044): ``artifacts/cracker.py`` loaded its two models from beside
# itself (cracker.py:68 and :75 in the recorded attempt); only the cracker and its requirements
# were declared, so the grader received neither model and the program printed nothing.
_VIGENERE_CRACKER = """import os

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))


def load_ngrams():
    return np.load(os.path.join(HERE, "english_ngrams.npz"))


def load_words():
    return np.load(os.path.join(HERE, "english_words.npz"))
"""


def _vigenere(tmp_path: Path) -> tuple[Path, object]:
    repository, base = _repository(tmp_path, {"README.md": "Cracker\n"})
    artifacts = repository / "artifacts"
    artifacts.mkdir()
    (artifacts / "cracker.py").write_text(_VIGENERE_CRACKER, encoding="utf-8")
    (artifacts / "requirements.txt").write_text("numpy\n", encoding="utf-8")
    (artifacts / "english_ngrams.npz").write_bytes(b"\x93NUMPY\x00\x01ngrams")
    (artifacts / "english_words.npz").write_bytes(b"\x93NUMPY\x00\x01words")
    return repository, base


def test_tb4n4_vigenere_names_each_undeclared_model_beside_the_cracker(tmp_path: Path) -> None:
    repository, base = _vigenere(tmp_path)
    delivered = (_item("artifacts/cracker.py"), _item("artifacts/requirements.txt"))

    assert _pairs(repository, base, _projection(*delivered)) == (
        ("artifacts/cracker.py", "artifacts/english_ngrams.npz"),
        ("artifacts/cracker.py", "artifacts/english_words.npz"),
    )
    # Declaring one model as a delivered output leaves only the other.
    assert _pairs(
        repository, base, _projection(*delivered, _item("artifacts/english_ngrams.npz"))
    ) == (("artifacts/cracker.py", "artifacts/english_words.npz"),)
    # Declaring both clears it.
    assert (
        _pairs(
            repository,
            base,
            _projection(
                *delivered,
                _item("artifacts/english_ngrams.npz"),
                _item("artifacts/english_words.npz"),
            ),
        )
        == ()
    )
    # So does a self-contained cracker that rebuilds its tables at run time.
    (repository / "artifacts" / "cracker.py").write_text(
        "NGRAMS = build_ngrams()\nWORDS = build_words()\n", encoding="utf-8"
    )
    assert _pairs(repository, base, _projection(*delivered)) == ()


def test_an_untracked_file_the_task_started_with_is_not_an_undeclared_dependency(
    tmp_path: Path,
) -> None:
    """#1044 blocks closure, so a task-provided data file must not stop the agent (#1045 baseline).

    The task-start base records the untracked files already present; one still unchanged is not
    part of the change, so it is never a created-file candidate. A model the agent creates is.
    """

    repository = tmp_path / "app"
    repository.mkdir(mode=0o700)
    _git(repository, "init", "--quiet")
    (repository / "README.md").write_text("Cracker\n", encoding="utf-8")
    _git(repository, "add", "--", "README.md")
    _git(
        repository,
        "-c",
        "user.name=FinishUP Test",
        "-c",
        "user.email=finishup@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "baseline",
    )
    artifacts = repository / "artifacts"
    artifacts.mkdir()
    # Provided with the task, never committed: untracked when the task starts.
    (artifacts / "english_words.npz").write_bytes(b"\x93NUMPY\x00\x01words")
    base = GitChangeCaptureAdapter().read_task_base(os.fspath(repository))
    (artifacts / "cracker.py").write_text(_VIGENERE_CRACKER, encoding="utf-8")
    (artifacts / "english_ngrams.npz").write_bytes(b"\x93NUMPY\x00\x01ngrams")

    assert _pairs(repository, base, _projection(_item("artifacts/cracker.py"))) == (
        ("artifacts/cracker.py", "artifacts/english_ngrams.npz"),
    )


def test_a_created_file_inside_a_nested_repository_is_an_undeclared_dependency(
    tmp_path: Path,
) -> None:
    """Review of #1045: the metadata read failed in any workspace holding an untracked nested
    repository, so the fact was silently never raised there. A file the agent creates inside the
    repository is a candidate; one it held unchanged since the task started is not."""

    repository, _ = _repository(tmp_path, {"README.md": "Cracker\n"})
    api = repository / "api"
    api.mkdir(mode=0o700)
    _git(api, "init", "--quiet")
    (api / "README.md").write_text("API\n", encoding="utf-8")
    _git(api, "add", "--", "README.md")
    _git(
        api,
        "-c",
        "user.name=FinishUP Test",
        "-c",
        "user.email=finishup@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "nested baseline",
    )
    # Provided with the task, never committed: untracked inside the nested repository.
    (api / "english_words.npz").write_bytes(b"\x93NUMPY\x00\x01words")
    base = GitChangeCaptureAdapter().read_task_base(os.fspath(repository))
    (api / "cracker.py").write_text(_VIGENERE_CRACKER, encoding="utf-8")
    (api / "english_ngrams.npz").write_bytes(b"\x93NUMPY\x00\x01ngrams")

    assert _pairs(repository, base, _projection(_item("api/cracker.py"))) == (
        ("api/cracker.py", "api/english_ngrams.npz"),
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


def test_adapter_returns_index_pairs_only_and_refuses_unsafe_paths(tmp_path: Path) -> None:
    from finishup.ports.change_capture import ChangeCaptureUnavailable

    repository, _base = _cracker(tmp_path)
    adapter = GitChangeCaptureAdapter()
    workspace = os.fspath(repository)
    found = adapter.find_undeclared_references(
        workspace, ("README.md", "cracker.py"), ("notes.npz", "english_model.npz")
    )
    # Positions in the caller's own tuples: no path or content leaves the adapter.
    assert found == ((1, 1),)
    assert adapter.find_undeclared_references(workspace, ("cracker.py",), ()) == ()
    for unsafe in ("../cracker.py", "/etc/passwd", "a/./b"):
        with pytest.raises(ChangeCaptureUnavailable):
            adapter.find_undeclared_references(workspace, (unsafe,), ("english_model.npz",))
    with pytest.raises(ChangeCaptureUnavailable):
        adapter.find_undeclared_references(workspace, ("x.py",) * 17, ("english_model.npz",))


def test_only_the_first_bounded_prefix_is_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import finishup.adapters.git_change_capture as capture_module

    repository, _base = _cracker(tmp_path, "#" * 64 + "\nload('english_model.npz')\n")
    adapter = GitChangeCaptureAdapter()
    workspace = os.fspath(repository)
    assert adapter.find_undeclared_references(workspace, ("cracker.py",), ("english_model.npz",))
    monkeypatch.setattr(capture_module, "_MAX_REFERENCE_FILE_BYTES", 32)
    assert not adapter.find_undeclared_references(
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

        def find_undeclared_references(self, *_arguments: object) -> object:
            raise RuntimeError("boom")

    async def run() -> tuple[tuple[str, str], ...]:
        states = await requested_output_states(
            projection=projection,
            capture=capture,
            source=source,
            port=adapter,
            request_id=_REQUEST,
        )
        read = await undeclared_references(
            projection=projection,
            capture=capture,
            source=source,
            port=Broken(),
            states=states,
            blocked=None,
            request_id=_REQUEST,
        )
        assert read.ambiguous == ()
        return read.pairs

    assert asyncio.run(run()) == ()


# tb4n5 biped-contact-dynamics D (the #1044 follow-up, ADR-035 amendment): ``solve.py`` only
# *writes* ``walk.npz``, ``run.npz`` and ``jump.npz`` (``model.export(..., out/'walk.npz')``, whose
# sink is ``np.savez_compressed``); the declared outputs ``results/*.npz`` carry the same names, and
# the agent's validator left 18 copies under ``checks/case_*/``. All 18 matched by basename and
# blocked closure. Lines 155, 181, 183, 268, 322, 405 and 414 of the recorded attempt, trimmed.
_BIPED_SOLVER = """import json
from pathlib import Path

import numpy as np


class Model:
    def export(self, path, pitch, momentum, duration, dt, output):
        t = np.arange(0.0, duration, dt)
        np.savez_compressed(output, t=t, state=t, u=t, contact_forces=t, mode=t)
        print(f'{output.name}: {len(t)} samples', flush=True)


def walking(model, cfg, out):
    model.export(path,lambda t:pp(phase(t)[1]),lambda t:hh(phase(t)[1]),steps*T,dt,out/'walk.npz')


def running(model, cfg, out):
    model.export(path,lambda t:pp(phase(t)[1]),lambda t:hh(phase(t)[1]),(steps-1)*T+ts,dt,out/'run.npz')


def jumping(model, cfg, out):
    model.export(path,lambda t:float(sol.sol(t)[0]),lambda t:0.,T,dt,out/'jump.npz')


def main():
    with args.config.open() as f:cfg=json.load(f)
"""
_MOTIONS = ("walk.npz", "run.npz", "jump.npz")


def _biped(tmp_path: Path, solver: str = _BIPED_SOLVER) -> tuple[Path, object]:
    repository, base = _repository(tmp_path, {"README.md": "Biped\n"})
    for directory in ("submission", "results", *(f"checks/case_{n}" for n in range(6))):
        (repository / directory).mkdir(parents=True)
    (repository / "submission" / "solve.py").write_text(solver, encoding="utf-8")
    for motion in _MOTIONS:
        (repository / "results" / motion).write_bytes(b"\x93NUMPY\x00\x01motion")
        for n in range(6):
            (repository / "checks" / f"case_{n}" / motion).write_bytes(b"\x93NUMPY\x00\x01copy")
    (repository / "checks" / "validate.py").write_text("print('ok')\n", encoding="utf-8")
    return repository, base


def _biped_delivery(*, results: bool = True) -> tuple[RequestedItem, ...]:
    declared = [_item("submission/solve.py")]
    if results:
        declared.extend(_item(f"results/{motion}") for motion in _MOTIONS)
    return tuple(declared)


def test_tb4n5_biped_writer_literals_raise_no_dependency_on_validation_copies(
    tmp_path: Path,
) -> None:
    repository, base = _biped(tmp_path)

    # The recorded shape: written by the solver, shared with the declared results, in another
    # directory. None of the 18 copies is a dependency.
    assert _pairs(repository, base, _projection(*_biped_delivery())) == ()
    # ``model.export`` is an unsupported wrapper, so its use is unknown, not a proven write; the
    # copies stay out because the bare name ``walk.npz`` is ambiguous: a declared file shares it,
    # and without the declared results nothing ties it to ``checks/case_*``.
    assert _pairs(repository, base, _projection(*_biped_delivery(results=False))) == ()
    adapter = GitChangeCaptureAdapter()
    copies = tuple(f"checks/case_{n}/{motion}" for n in range(6) for motion in _MOTIONS)
    kinds = adapter.classify_undeclared_references(
        os.fspath(repository), ("submission/solve.py",), copies, ("results/walk.npz",)
    )
    # Every copy is named only ambiguously: counted for the receipt, never a dependency.
    assert {kind for _deliverable, _candidate, kind in kinds} == {"ambiguous"}
    assert len(kinds) == len(copies)


def test_a_basename_shared_with_a_declared_file_or_in_an_unrelated_directory_is_ambiguous(
    tmp_path: Path,
) -> None:
    """A *read* of a bare ``walk.npz`` still names no copy: the declared ``results/walk.npz`` has
    that name, and no literal ties the reference to ``checks/case_*``."""

    reader = "import numpy as np\nWALK = np.load('walk.npz')\n"
    repository, base = _biped(tmp_path, reader)
    assert _pairs(repository, base, _projection(*_biped_delivery())) == ()
    assert _pairs(repository, base, _projection(*_biped_delivery(results=False))) == ()
    # A literal that names the copies' directory ties the reference to it: a dependency again.
    (repository / "submission" / "solve.py").write_text(
        "import os\nimport numpy as np\n"
        "WALK = np.load(os.path.join('checks', 'case_0', 'walk.npz'))\n",
        encoding="utf-8",
    )
    assert _pairs(repository, base, _projection(*_biped_delivery(results=False))) == (
        ("submission/solve.py", "checks/case_0/walk.npz"),
    )


def test_same_basename_in_two_directories_resolves_to_the_one_beside_the_deliverable(
    tmp_path: Path,
) -> None:
    repository, base = _repository(tmp_path, {"README.md": "Two models\n"})
    for directory in ("a", "b", "c"):
        (repository / directory).mkdir()
    for directory in ("a", "b"):
        (repository / directory / "model.npz").write_bytes(b"\x93NUMPY\x00\x01model")
    loader = "import numpy as np\nMODEL = np.load('model.npz')\n"
    (repository / "a" / "run.py").write_text(loader, encoding="utf-8")
    (repository / "c" / "run.py").write_text(loader, encoding="utf-8")
    assert _pairs(repository, base, _projection(_item("a/run.py"))) == (
        ("a/run.py", "a/model.npz"),
    )
    # From a third directory neither copy is tied to the bare name: ambiguous, not reported.
    assert _pairs(repository, base, _projection(_item("c/run.py"))) == ()


@pytest.mark.parametrize(
    "line",
    [
        "frame.to_csv('weights.npz', index=False)",
        "frame.to_parquet(path='weights.npz')",
        "np.savez(os.path.join(HERE, 'weights.npz'), **tables)",
        "np.savez_compressed(Path(HERE) / 'weights.npz', **tables)",
        "np.save(file='weights.npz', arr=tables)",
        "Path('weights.npz').write_bytes(data)",
        "(HERE / 'weights.npz').write_bytes(data)",
        "json.dump(obj, open('weights.npz', 'w'))",
        "handle = open('weights.npz', mode='wb')",
        "handle = open(os.path.join(HERE, 'weights.npz'), 'w')",
        "torch.save(state, 'weights.npz')",
        "plt.savefig('weights.npz')",
        "os.remove('weights.npz')",
        # A container opener's write-only modes truncate or create.
        "with zipfile.ZipFile('weights.npz', 'w') as archive: archive.writestr('a', b'')",
        "store = h5py.File('weights.npz', mode='w')",
    ],
)
def test_a_literal_the_deliverable_only_writes_is_not_a_dependency(
    tmp_path: Path, line: str
) -> None:
    repository, base = _repository(tmp_path, {"README.md": "Writer\n"})
    (repository / "train.py").write_text(
        f"import json, os\nfrom pathlib import Path\nHERE = Path(__file__).parent\n{line}\n",
        encoding="utf-8",
    )
    (repository / "weights.npz").write_bytes(b"\x93NUMPY\x00\x01weights")
    assert _pairs(repository, base, _projection(_item("train.py"))) == ()


@pytest.mark.parametrize(
    "line",
    [
        "MODEL = np.load('weights.npz')",
        "MODEL = np.load(os.path.join(HERE, 'weights.npz'))",
        "MODEL = torch.load(Path(HERE) / 'weights.npz')",
        "TEXT = (HERE / 'weights.npz').read_bytes()",
        "with open('weights.npz', 'rb') as handle: MODEL = handle.read()",
        "with open('weights.npz') as handle: MODEL = handle.read()",
        "MODEL_PATH = HERE / 'weights.npz'",
        # Checker reproduction (#4): the default mode reads; a directory literal is not a mode.
        "with open(os.path.join('.', 'weights.npz')) as handle: MODEL = handle.read()",
        "with open(os.path.join('.', 'weights.npz'), encoding='utf-8') as handle: MODEL = 1",
        # ZipFile.write reads its source file into the archive.
        "archive.write('weights.npz')",
        # An unsupported wrapper is unknown, never a proven write.
        "save_model(model, 'weights.npz')",
        "export_report(data, os.path.join(HERE, 'weights.npz'))",
        "model.save('weights.npz')",
        # Checker reproduction (R2 #4): a container's append and read-write modes read it.
        "with zipfile.ZipFile('weights.npz', 'a') as archive:\n    weights = archive.read('trained')",
        "archive = zipfile.ZipFile('weights.npz', mode='a')",
        "store = h5py.File('weights.npz', 'a')",
        "store = h5py.File('weights.npz', 'r+')",
        # A method named ``open`` on another receiver is not the builtin: its modes are unproven.
        "bundle = tarfile.open('weights.npz', 'a')",
    ],
)
def test_a_read_or_an_unclassified_use_is_still_a_dependency(tmp_path: Path, line: str) -> None:
    repository, base = _repository(tmp_path, {"README.md": "Reader\n"})
    (repository / "serve.py").write_text(
        "import os\nfrom pathlib import Path\nimport numpy as np\n"
        f"HERE = Path(__file__).parent\n{line}\n",
        encoding="utf-8",
    )
    (repository / "weights.npz").write_bytes(b"\x93NUMPY\x00\x01weights")
    assert _pairs(repository, base, _projection(_item("serve.py"))) == (
        ("serve.py", "weights.npz"),
    )


def test_an_explicit_directory_read_beats_a_declared_namesake_and_a_beside_source_decoy(
    tmp_path: Path,
) -> None:
    """Checker reproductions (#3): a path built from literals names its directory explicitly.

    ``np.load(os.path.join('checks', 'case_0', 'walk.npz'))`` reads that copy even though the
    declared ``results/walk.npz`` shares its name, and ``os.path.join('b', 'model.npz')`` from
    ``a/serve.py`` reads ``b/model.npz``, never the ``a/model.npz`` beside the deliverable.
    """

    reader = (
        "import os\nimport numpy as np\n"
        "WALK = np.load(os.path.join('checks', 'case_0', 'walk.npz'))\n"
    )
    for directory in ("biped", "decoy"):
        (tmp_path / directory).mkdir()
    repository, base = _biped(tmp_path / "biped", reader)
    assert _pairs(repository, base, _projection(*_biped_delivery())) == (
        ("submission/solve.py", "checks/case_0/walk.npz"),
    )
    # The same through the ``/`` operator on ``Path``.
    (repository / "submission" / "solve.py").write_text(
        "from pathlib import Path\nimport numpy as np\n"
        "WALK = np.load(Path('checks') / 'case_0' / 'walk.npz')\n",
        encoding="utf-8",
    )
    assert _pairs(repository, base, _projection(*_biped_delivery())) == (
        ("submission/solve.py", "checks/case_0/walk.npz"),
    )

    repository, base = _repository(tmp_path / "decoy", {"README.md": "Two models\n"})
    for directory in ("a", "b"):
        (repository / directory).mkdir()
        (repository / directory / "model.npz").write_bytes(b"\x93NUMPY\x00\x01model")
    (repository / "a" / "serve.py").write_text(
        "import os\nimport numpy as np\nMODEL = np.load(os.path.join('b', 'model.npz'))\n",
        encoding="utf-8",
    )
    assert _pairs(repository, base, _projection(_item("a/serve.py"))) == (
        ("a/serve.py", "b/model.npz"),
    )
    # A directory literal is never mistaken for ``open``'s mode: the default mode reads.
    (repository / "a" / "serve.py").write_text(
        "import os\nwith open(os.path.join('b', 'model.npz')) as handle:\n    DATA = handle.read()\n",
        encoding="utf-8",
    )
    assert _pairs(repository, base, _projection(_item("a/serve.py"))) == (
        ("a/serve.py", "b/model.npz"),
    )


def test_read_before_write_is_a_dependency(tmp_path: Path) -> None:
    """A cache the deliverable loads when present and writes otherwise still needs delivering."""

    repository, base = _vigenere(tmp_path)
    (repository / "artifacts" / "cracker.py").write_text(
        "import os\nimport numpy as np\nHERE = os.path.dirname(os.path.abspath(__file__))\n"
        "def tables():\n"
        "    if os.path.exists(os.path.join(HERE, 'english_ngrams.npz')):\n"
        "        return np.load(os.path.join(HERE, 'english_ngrams.npz'))\n"
        "    built = build()\n"
        "    np.savez(os.path.join(HERE, 'english_ngrams.npz'), **built)\n"
        "    return built\n",
        encoding="utf-8",
    )
    delivered = (_item("artifacts/cracker.py"), _item("artifacts/requirements.txt"))
    assert _pairs(repository, base, _projection(*delivered)) == (
        ("artifacts/cracker.py", "artifacts/english_ngrams.npz"),
    )


def test_a_runtime_rebuild_that_keeps_its_output_literals_raises_nothing(
    tmp_path: Path,
) -> None:
    """The vigenere repair "rebuild it at run time" may still name the files it writes."""

    repository, base = _vigenere(tmp_path)
    (repository / "artifacts" / "cracker.py").write_text(
        "import os\nimport numpy as np\nHERE = os.path.dirname(os.path.abspath(__file__))\n"
        "NGRAMS = build_ngrams()\nWORDS = build_words()\n"
        "np.savez(os.path.join(HERE, 'english_ngrams.npz'), **NGRAMS)\n"
        "np.savez(os.path.join(HERE, 'english_words.npz'), **WORDS)\n",
        encoding="utf-8",
    )
    delivered = (_item("artifacts/cracker.py"), _item("artifacts/requirements.txt"))
    assert _pairs(repository, base, _projection(*delivered)) == ()


def test_shell_redirections_and_string_or_comment_parentheses(tmp_path: Path) -> None:
    repository, base = _repository(tmp_path, {"README.md": "Shell\n"})
    (repository / "report.txt").write_text("report\n", encoding="utf-8")
    (repository / "input.txt").write_text("input\n", encoding="utf-8")
    (repository / "run.sh").write_text(
        '#!/bin/sh\npython gen.py > "report.txt"\nsort < "input.txt"\n', encoding="utf-8"
    )
    assert _pairs(repository, base, _projection(_item("run.sh"))) == (("run.sh", "input.txt"),)
    # A parenthesis inside a string or a comment does not move the call that holds the literal.
    (repository / "tool.py").write_text(
        "print('(')  # unbalanced ( in a comment\nnp.save('report.txt', data)\n", encoding="utf-8"
    )
    assert _pairs(repository, base, _projection(_item("tool.py"))) == ()


def test_an_archive_opened_for_append_reads_its_existing_members(tmp_path: Path) -> None:
    """Checker reproduction (R2 #4): ``ZipFile(..., 'a')`` reads the members already in the
    archive, so the deliverable needs the file: it is a dependency, never a proven write."""

    repository, base = _repository(tmp_path, {"README.md": "Archive\n"})
    archive_path = repository / "weights.npz"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("trained", "learned parameters")
    with zipfile.ZipFile(archive_path, "a") as archive:
        assert archive.read("trained") == b"learned parameters"
    (repository / "serve.py").write_text(
        "import zipfile\n"
        "with zipfile.ZipFile('weights.npz', 'a') as archive:\n"
        "    weights = archive.read('trained')\n",
        encoding="utf-8",
    )
    assert _pairs(repository, base, _projection(_item("serve.py"))) == (
        ("serve.py", "weights.npz"),
    )


class _CountingNames(dict[bytes, list[int]]):
    """A basename index that counts how often a naming's candidate list is materialized."""

    lookups = 0

    def get(self, key: bytes, default: object = None) -> object:  # type: ignore[override]
        type(self).lookups += 1
        return super().get(key, default)


@pytest.mark.parametrize("line", ["x = 'weights.npz'\n", "np.save('weights.npz', x)\n"])
def test_matcher_state_is_bounded_by_candidates_not_occurrences(line: str) -> None:
    """Checker reproduction (R2 #6): a 256-KiB-bounded deliverable repeating one literal against
    1,024 candidates sharing its basename stays small. Each candidate keeps one aggregate and a
    naming's candidate list is applied once, not once per occurrence."""

    source = (line * 16_384).encode()[: 256 * 1024]
    candidates = tuple(f"copies/{index:04}/weights.npz".encode() for index in range(1_024))
    paths: dict[bytes, list[int]] = {}
    names = _CountingNames()
    for index, candidate in enumerate(candidates):
        paths.setdefault(candidate, []).append(index)
        names.setdefault(candidate.rsplit(b"/", 1)[-1], []).append(index)
    _CountingNames.lookups = 0
    tracemalloc.start()
    try:
        found, ambiguous = _dependencies(
            source, b"serve.py", candidates, paths, names, frozenset(), b".py"
        )
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert found == set()
    assert len(ambiguous) == 1_024
    # Proven writes are classified up to the occurrence bound; after it, and for any unproven
    # use, one application per naming.
    assert _CountingNames.lookups <= _MAX_CLASSIFIED_OCCURRENCES + 1
    # The per-occurrence state measured about 750 MiB; the aggregate stays under a few MiB.
    assert peak < 8 * 1024 * 1024
