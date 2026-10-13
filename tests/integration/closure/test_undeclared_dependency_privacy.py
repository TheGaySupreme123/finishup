"""tb4n5 biped-contact-dynamics D: names of undeclared files under the private privacy ceiling.

The run's policy (``agent/setup/25-verify-privacy-show.json``: ``local_only``, structural review,
an ``agent_context`` ceiling of bounded_structural_metadata, declared_file_type, finding_summary
and obligation_text, no ``repository_excerpt``) is exactly the shipped default. Under it every
path in ``closure_readiness.undeclared_references`` was withheld, the Stop gate printed "(path
withheld)" and the agent spent about a dozen guidance reads guessing what to declare.

Owner decision (2026-10-13): Yoetz may show the agent, locally, the names of files the agent's own
task created (``task_created_file`` provenance), never egressed. "Created by the task" is the
check-time change against the task-start base, whose complete untracked listing proves a file did
not predate the task. These tests drive a real repository through the real adapter, the real
check and status, the daemon's exact post-commit projection with the production-composed
enforcer, the audit receipt and the Stop gate. A file that predated the task stays withheld and
the gate says how to list created files with the agent's own shell; an owner who granted
``repository_excerpt`` sees every name.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import os
import subprocess
from collections.abc import Callable, Mapping, Sequence
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest

from builders.projection_workflow import (
    ProjectionCase,
    build_projection_application,
    frontier_json,
    project_case,
    request_base,
)
from builders.start_application import protocol_id, start_request
from yoetz.adapters.git_change_capture import GitChangeCaptureAdapter
from yoetz.adapters.memory.privacy import MemoryPrivacyAudit
from yoetz.application import check_change
from yoetz.application.check import CheckCommitResult
from yoetz.application.publish_work import PublishWorkInternalResult
from yoetz.application.service import Application
from yoetz.application.start import StartInternalResult
from yoetz.application.status import StatusInternalResult
from yoetz.cli.closure_gate import closure_gate_from_readiness
from yoetz.domain.privacy import (
    AgentProjectionAuditSubject,
    DataCategory,
    DisclosureProvenance,
    PrivacyPolicy,
)
from yoetz.domain.task_fact_tokens import DELIVERABLE_REFERENCES_UNDECLARED_FILE_GAP
from yoetz.ports.change_capture import CheckWorkspaceSource, TaskChangeBase
from yoetz.ports.control import ControlMethod
from yoetz.protocol.canonical import JsonValue
from yoetz.protocol.models import (
    CheckRequest,
    PublishWorkRequest,
    ReceiptRequest,
    StatusRequest,
    StatusResultModel,
)

pytestmark = pytest.mark.anyio

_CODE = DELIVERABLE_REFERENCES_UNDECLARED_FILE_GAP
_OBLIGATION = protocol_id("obl_", 9101)
_CRACKER = "artifacts/cracker.py"
_MODELS = ("artifacts/english_ngrams.npz", "artifacts/english_words.npz")
_LOADER = """import os

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
NGRAMS = np.load(os.path.join(HERE, "english_ngrams.npz"))
WORDS = np.load(os.path.join(HERE, "english_words.npz"))
"""
_GIT_ENV = {
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
    "LANG": "C",
    "LC_ALL": "C",
    "PATH": os.defpath,
}


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


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


def _workspace(tmp_path: Path, *, preexisting_model: bool = False) -> tuple[Path, TaskChangeBase]:
    """A repository at task start, then the cracker and its models the task creates.

    With ``preexisting_model`` the words model was already in the working tree, untracked, when
    the task started, and the task only staged it: it is in the change, but not created by it.
    """

    repository = tmp_path / "app"
    repository.mkdir(mode=0o700)
    _git(repository, "init", "--quiet")
    (repository / "README.md").write_text("Cracker\n", encoding="utf-8")
    _git(repository, "add", "--", "README.md")
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
    artifacts = repository / "artifacts"
    artifacts.mkdir()
    if preexisting_model:
        (artifacts / "english_words.npz").write_bytes(b"\x93NUMPY\x00\x01words")
    base = GitChangeCaptureAdapter().read_task_base(os.fspath(repository))
    assert base.origin == "task_start" and base.untracked_complete
    (artifacts / "cracker.py").write_text(_LOADER, encoding="utf-8")
    (artifacts / "english_ngrams.npz").write_bytes(b"\x93NUMPY\x00\x01ngrams")
    if preexisting_model:
        _git(repository, "add", "--", "artifacts/english_words.npz")
    else:
        (artifacts / "english_words.npz").write_bytes(b"\x93NUMPY\x00\x01words")
    return repository, base


def _bind_workspace(
    monkeypatch: pytest.MonkeyPatch, repository: Path, base: TaskChangeBase | None
) -> None:
    """Run the real workspace reads against *repository*: the application has no bound workspace.

    The check's own probes (``requested_output_states``, ``undeclared_references``) and the
    created-in-task proof (``created_since_task_start``) are the production functions, given the
    real adapter, a real metadata capture and the real task-start base.
    """

    adapter = GitChangeCaptureAdapter()
    source = CheckWorkspaceSource(os.fspath(repository), "hmac-sha256:" + "0" * 64)
    real_states = check_change.requested_output_states
    real_references = check_change.undeclared_references
    real_created = check_change.created_since_task_start

    def capture() -> Any:
        return adapter.capture_metadata(os.fspath(repository), base)

    async def states(**kwargs: Any) -> Any:
        return await real_states(
            projection=kwargs["projection"],
            capture=capture(),
            source=source,
            port=adapter,
            request_id=kwargs["request_id"],
        )

    async def references(**kwargs: Any) -> Any:
        return await real_references(
            projection=kwargs["projection"],
            capture=capture(),
            source=source,
            port=adapter,
            states=kwargs["states"],
            blocked=kwargs["blocked"],
            request_id=kwargs["request_id"],
        )

    monkeypatch.setattr(check_change, "requested_output_states", states)
    monkeypatch.setattr(check_change, "undeclared_references", references)

    def created(_capture: object, _base: object) -> Callable[[str], bool]:
        return real_created(capture(), base)

    monkeypatch.setattr(check_change, "created_since_task_start", created)


def _draft(seed: int, name: str, payload: dict[str, JsonValue], version: str = "1.0.0") -> Any:
    return {
        "event_id": protocol_id("evt_", seed),
        "schema": {"name": name, "version": version},
        "occurred_at": "2026-10-13T12:00:00.000Z",
        "causal_parents": [],
        "payload": payload,
        "artifact_refs": [],
        "evidence_refs": [],
    }


async def _run(
    app: Application,
    seed: int,
    delivered: tuple[str, ...] = (_CRACKER,),
    *,
    expect_gap: bool = True,
) -> tuple[StartInternalResult, Any]:
    """The cracker delivered and claimed with only the cracker declared, then one check."""

    started = await app.start(start_request(seed, title="Vigenere cracker", refs=True))
    assert type(started) is StartInternalResult
    evidence = protocol_id("evd_", seed + 1)
    items: list[JsonValue] = [
        {"item_kind": "file", "value": value, "role": "output"} for value in delivered
    ]
    obligation: dict[str, JsonValue] = {
        "obligation_id": _OBLIGATION,
        "description": "Deliver the cracker",
        "acceptance_criteria": "The cracker recovers the plaintexts.",
        "evidence_expectation": "The sample run.",
        "status": "open",
        "requested_items": items,
    }
    drafts = [
        _draft(seed + 2, "obligation_published", obligation, "1.1.0"),
        _draft(
            seed + 3,
            "plan_published",
            {"plan_version": 1, "summary": "Cracker", "obligation_refs": [_OBLIGATION]},
        ),
        _draft(
            seed + 4,
            "action_recorded",
            {
                "action_id": protocol_id("act_", seed + 5),
                "action_kind": "other",
                "description": "Wrote the cracker and its models",
                "obligation_refs": [_OBLIGATION],
                "attempted_items": list(delivered),
            },
        ),
        _draft(
            seed + 6,
            "result_recorded",
            {
                "result_id": protocol_id("res_", seed + 7),
                "action_id": protocol_id("act_", seed + 5),
                "outcome": "success",
                "summary": "The cracker recovers the sample plaintexts.",
            },
        ),
        _draft(
            seed + 8,
            "evidence_recorded",
            {
                "evidence_id": evidence,
                "evidence_kind": "test_result",
                "strength": "metadata_only",
                "observed_at": "2026-10-13T12:00:00.000Z",
                "description": "The cracker recovered every sample plaintext.",
            },
        ),
        _draft(
            seed + 9,
            "obligation_published",
            {**obligation, "status": "resolved", "resolution_evidence_refs": [evidence]},
            "1.1.0",
        ),
        _draft(
            seed + 10,
            "claim_recorded",
            {
                "claim_id": protocol_id("clm_", seed + 11),
                "claim_kind": "completion",
                "statement": "The cracker is delivered.",
                "supporting_refs": [evidence],
                "obligation_refs": [_OBLIGATION],
                "limitation_refs": [],
                "supersedes_claim_refs": [],
            },
            "1.1.0",
        ),
    ]
    published = await app.publish_work(
        PublishWorkRequest.model_validate(
            {
                **request_base(protocol_id("req_", seed + 12)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": frontier_json(started.frontier),
                "event_drafts": drafts,
            }
        )
    )
    assert type(published) is PublishWorkInternalResult
    checked = await app.check(
        CheckRequest.model_validate(
            {
                **request_base(protocol_id("req_", seed + 13)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": frontier_json(published.result_frontier),
                "mode": "deterministic_only",
            }
        )
    )
    assert type(checked) is CheckCommitResult
    assert (_CODE in checked.coverage.known_gaps) is expect_gap
    return started, checked


async def _projected_status(
    app: Application, started: StartInternalResult, seed: int
) -> tuple[StatusInternalResult, Mapping[str, JsonValue]]:
    body: dict[str, JsonValue] = {
        **request_base(protocol_id("req_", seed)),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "view": "compact",
        "limit": "10",
    }
    internal = await app.status(StatusRequest.model_validate(body))
    assert type(internal) is StatusInternalResult
    projected = await project_case(
        app, ProjectionCase("status/compact", ControlMethod.STATUS, body, internal), seed + 1
    )
    return internal, projected


def _rows(projected: Mapping[str, JsonValue]) -> list[Mapping[str, JsonValue]]:
    readiness = cast(Mapping[str, JsonValue], projected["closure_readiness"])
    return list(cast(Sequence[Mapping[str, JsonValue]], readiness["undeclared_references"]))


def _gate_text(projected: Mapping[str, JsonValue]) -> str:
    """The Stop gate as the hook renders it, from the projected (agent-context) status."""

    model = StatusResultModel.model_validate(projected).root
    gate = closure_gate_from_readiness(
        cast(Any, model).closure_readiness,
        frontier_sequence="9",
        frontier_digest="d",
        observation_pending=False,
    )
    assert gate is not None and _CODE in gate.items
    return gate.text


def _audit(app: Application) -> MemoryPrivacyAudit:
    audit = app.privacy._audit  # noqa: SLF001
    assert type(audit) is MemoryPrivacyAudit
    return audit


def _projection_subject(app: Application, projected: Mapping[str, JsonValue]) -> Any:
    receipt_id = cast(Mapping[str, JsonValue], projected["privacy_projection"])[
        "local_disclosure_receipt_id"
    ]
    (row,) = [
        row
        for row in _audit(app)._state.audit.values()  # noqa: SLF001
        if row.receipt is not None and row.receipt.receipt_id == receipt_id
    ]
    assert type(row.subject) is AgentProjectionAuditSubject
    return row.subject


async def test_biped_private_ceiling_names_the_files_the_task_created(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, base = _workspace(tmp_path)
    _bind_workspace(monkeypatch, repository, base)
    app, policy = await build_projection_application(seed=9100)
    # The exact biped ceiling.
    assert set(policy.agent_context_categories) == {
        DataCategory.BOUNDED_STRUCTURAL_METADATA,
        DataCategory.DECLARED_FILE_TYPE,
        DataCategory.FINDING_SUMMARY,
        DataCategory.OBLIGATION_TEXT,
    }
    started, _checked = await _run(app, 9100)

    internal, projected = await _projected_status(app, started, 9150)
    (row,) = _rows(projected)
    assert row["obligation_id"] == _OBLIGATION
    assert row["name_provenance"] == "created_in_task"
    assert row["paths"] == list(_MODELS)
    assert internal.created_file_pointers == (
        "/closure_readiness/undeclared_references/0/paths/0",
        "/closure_readiness/undeclared_references/0/paths/1",
    )
    # Recorded on the projection's own audit subject, as every provenance class is.
    subject = _projection_subject(app, projected)
    assert DisclosureProvenance.TASK_CREATED_FILE in subject.provenance
    # The Stop gate names them and needs no listing continuation.
    text = _gate_text(projected)
    assert '"artifacts/english_ngrams.npz" and "artifacts/english_words.npz"' in text
    assert "git status" not in text


async def test_a_file_that_predated_the_task_stays_withheld_with_a_typed_continuation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, base = _workspace(tmp_path, preexisting_model=True)
    _bind_workspace(monkeypatch, repository, base)
    app, _policy = await build_projection_application(seed=9200)
    started, _checked = await _run(app, 9200)

    internal, projected = await _projected_status(app, started, 9250)
    (row,) = _rows(projected)
    # One of the two files was in the working tree before the task: the row is unproven, so
    # neither name returns without the repository-excerpt grant.
    assert row["name_provenance"] == "creation_unproven"
    assert row["total"] == "2"
    omitted = {
        "category": "repository_excerpt",
        "omitted": True,
        "reason": "local_disclosure_not_authorized",
    }
    assert row["paths"] == [omitted, omitted]
    assert internal.created_file_pointers == ()
    subject = _projection_subject(app, projected)
    assert DisclosureProvenance.TASK_CREATED_FILE not in subject.provenance
    text = _gate_text(projected)
    assert f"{_OBLIGATION} item 0 names (path withheld) and (path withheld)." in text
    assert "Yoetz could not prove your task created them" in text
    assert "`git status --porcelain --untracked-files=all`" in text
    assert "or their directory" in text
    for model in _MODELS:
        assert model.rsplit("/", 1)[1] not in str(projected)
        assert model.rsplit("/", 1)[1] not in text


async def test_without_a_task_start_base_no_name_is_task_created(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, _base = _workspace(tmp_path)
    # A first-check base (no task-start snapshot) cannot prove what predates the task.
    _bind_workspace(monkeypatch, repository, None)
    app, _policy = await build_projection_application(seed=9300)
    started, _checked = await _run(app, 9300)
    _internal, projected = await _projected_status(app, started, 9350)
    (row,) = _rows(projected)
    assert row["name_provenance"] == "creation_unproven"
    paths = cast(Sequence[Mapping[str, JsonValue]], row["paths"])
    assert paths and all(path["omitted"] is True for path in paths)


async def test_an_owner_who_granted_repository_excerpts_sees_every_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, base = _workspace(tmp_path, preexisting_model=True)
    _bind_workspace(monkeypatch, repository, base)

    def granted(policy: PrivacyPolicy) -> PrivacyPolicy:
        return replace(
            policy,
            agent_context_categories=(
                *policy.agent_context_categories,
                DataCategory.REPOSITORY_EXCERPT,
            ),
        )

    app, policy = await build_projection_application(seed=9400, policy_transform=granted)
    assert DataCategory.REPOSITORY_EXCERPT in policy.agent_context_categories
    started, _checked = await _run(app, 9400)
    _internal, projected = await _projected_status(app, started, 9450)
    (row,) = _rows(projected)
    assert row["name_provenance"] == "creation_unproven"
    assert row["paths"] == list(_MODELS)
    assert "git status" not in _gate_text(projected)


# The biped shape through every surface: the solver only writes the motion files, the declared
# results share their names, and the validator's 18 copies sit in ``checks/case_*``.
_BIPED_SOLVER = """from pathlib import Path

import numpy as np


class Model:
    def export(self, path, pitch, momentum, duration, dt, output):
        np.savez_compressed(output, t=np.arange(0.0, duration, dt))


def generate(model, out):
    model.export(path, pp, hh, 1.0, 0.01, out / 'walk.npz')
    model.export(path, pp, hh, 1.0, 0.01, out / 'run.npz')
    model.export(path, pp, hh, 1.0, 0.01, out / 'jump.npz')
"""
_MOTIONS = ("walk.npz", "run.npz", "jump.npz")


def _biped_workspace(tmp_path: Path) -> tuple[Path, TaskChangeBase]:
    repository, base = _workspace(tmp_path)
    for directory in ("submission", "results", *(f"checks/case_{n}" for n in range(6))):
        (repository / directory).mkdir(parents=True)
    (repository / "submission" / "solve.py").write_text(_BIPED_SOLVER, encoding="utf-8")
    for motion in _MOTIONS:
        (repository / "results" / motion).write_bytes(b"\x93NUMPY\x00\x01motion")
        for n in range(6):
            (repository / "checks" / f"case_{n}" / motion).write_bytes(b"\x93NUMPY\x00\x01copy")
    return repository, base


async def test_biped_writer_and_validation_copies_raise_nothing_on_any_surface(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Check, status (raw and projected), the Stop gate and the receipt agree: no gap."""

    repository, base = _biped_workspace(tmp_path)
    _bind_workspace(monkeypatch, repository, base)
    app, _policy = await build_projection_application(seed=9500)
    delivered = ("submission/solve.py", *(f"results/{motion}" for motion in _MOTIONS))
    started, checked = await _run(app, 9500, delivered, expect_gap=False)
    assert checked.overall_next is None or _OBLIGATION not in checked.overall_next.target_refs

    internal, projected = await _projected_status(app, started, 9550)
    readiness = internal.closure_readiness
    assert _CODE not in (readiness.agent_actionable or ())
    assert _CODE not in (readiness.standing_limitations or ())
    assert readiness.undeclared_references is None
    assert "undeclared_references" not in cast(
        Mapping[str, JsonValue], projected["closure_readiness"]
    )
    model = StatusResultModel.model_validate(projected).root
    gate = closure_gate_from_readiness(
        cast(Any, model).closure_readiness,
        frontier_sequence="9",
        frontier_digest="d",
        observation_pending=False,
    )
    assert gate is None or _CODE not in gate.items
    receipt = await app.receipt(
        ReceiptRequest.model_validate(
            {
                **request_base(protocol_id("req_", 9560)),
                "task_id": started.task_id,
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": frontier_json(internal.result_frontier),
                "format": "json",
                "include": "full",
                "redaction_profile": "full_local",
            }
        )
    )
    assert _CODE not in str(receipt.as_json())
