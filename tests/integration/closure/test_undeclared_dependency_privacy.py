"""tb4n5 biped-contact-dynamics D: names of undeclared files under the private privacy ceiling.

The run's policy (``agent/setup/25-verify-privacy-show.json``: ``local_only``, structural review,
an ``agent_context`` ceiling of bounded_structural_metadata, declared_file_type, finding_summary
and obligation_text, no ``repository_excerpt``) is exactly the shipped default. Under it every
path in ``closure_readiness.undeclared_references`` was withheld, the Stop gate printed "(path
withheld)" and the agent spent about a dozen guidance reads guessing what to declare.

Owner decision (2026-10-13): FinishUP may show the agent, locally, the names of files the agent
itself created. The checker's review showed that "appeared during the task" is not that: a file
staged before the task, an ignored file force-added later, or one another process wrote all
appear in the change, and no structural record ties a shell-created file to its creator. So the
exception fails closed: a name returns only to the writer who published that exact name itself,
in this session, through a cooperative channel (the ordinary ``self_authored`` rule, keyed on the
name's own leaf). Every other name keeps the category ceiling, and the Stop gate gives the typed
continuation: the omission, the count, and the agent's own shell command that lists what its
change created. These tests drive a real repository through the real adapter, the real check and
status, the daemon's exact post-commit projection with the production-composed enforcer, the
audit receipt and the Stop gate.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import os
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import replace
from datetime import UTC, datetime
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
from finishup.adapters.git_change_capture import GitChangeCaptureAdapter
from finishup.adapters.memory.privacy import MemoryPrivacyAudit
from finishup.application import check_change
from finishup.application.check import CheckCommitResult
from finishup.application.publish_work import PublishWorkInternalResult
from finishup.application.service import Application
from finishup.application.start import StartInternalResult
from finishup.application.status import StatusInternalResult
from finishup.cli.closure_gate import closure_gate_from_readiness
from finishup.domain.events import (
    EventDraft,
    EventSchema,
    RedactionMethod,
    RedactionReasonCategory,
    RedactionRecordedPayload,
    encode_payload,
)
from finishup.domain.privacy import (
    AgentProjectionAuditSubject,
    DataCategory,
    DisclosureProvenance,
    PrivacyPolicy,
)
from finishup.domain.task_fact_tokens import DELIVERABLE_REFERENCES_UNDECLARED_FILE_GAP
from finishup.domain.values import actor_id, event_id, timestamp_from_datetime
from finishup.ports.change_capture import CheckWorkspaceSource, TaskChangeBase
from finishup.ports.control import ControlMethod
from finishup.protocol.canonical import JsonValue, canonical_encode
from finishup.protocol.coverage import PublicationChannel
from finishup.protocol.models import (
    CheckRequest,
    PublishWorkRequest,
    ReceiptRequest,
    StatusRequest,
    StatusResultModel,
)
from integration.application import test_evidence_readback as readback

pytestmark = pytest.mark.anyio

_CODE = DELIVERABLE_REFERENCES_UNDECLARED_FILE_GAP
_AMBIGUOUS = "deliverable_references_ambiguous_name"
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


def _workspace(tmp_path: Path, *, words: str = "created") -> tuple[Path, TaskChangeBase]:
    """A repository at task start, then the cracker and its models.

    ``words`` says how the words model got into the change: ``created`` during the task (by a
    shell or another process, FinishUP cannot tell), ``prestaged`` (staged as an addition before the
    task started, so absent from both HEAD and the untracked listing), or ``ignored`` (ignored and
    present at task start, force-added later).
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
        "user.email=yoetz@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "baseline",
    )
    artifacts = repository / "artifacts"
    artifacts.mkdir()
    if words == "prestaged":
        (artifacts / "english_words.npz").write_bytes(b"\x93NUMPY\x00\x01words")
        _git(repository, "add", "--", "artifacts/english_words.npz")
    elif words == "ignored":
        (repository / ".gitignore").write_text("*.npz\n", encoding="utf-8")
        _git(repository, "add", "--", ".gitignore")
        _git(
            repository,
            "-c",
            "user.name=FinishUP Test",
            "-c",
            "user.email=yoetz@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "ignore models",
        )
        (artifacts / "english_words.npz").write_bytes(b"\x93NUMPY\x00\x01words")
    base = GitChangeCaptureAdapter().read_task_base(os.fspath(repository))
    assert base.origin == "task_start" and base.untracked_complete
    (artifacts / "cracker.py").write_text(_LOADER, encoding="utf-8")
    (artifacts / "english_ngrams.npz").write_bytes(b"\x93NUMPY\x00\x01ngrams")
    if words == "ignored":
        _git(repository, "add", "-f", "--", "artifacts/english_ngrams.npz")
        _git(repository, "add", "-f", "--", "artifacts/english_words.npz")
    elif words == "created":
        (artifacts / "english_words.npz").write_bytes(b"\x93NUMPY\x00\x01words")
    return repository, base


def _bind_workspace(
    monkeypatch: pytest.MonkeyPatch, repository: Path, base: TaskChangeBase | None
) -> None:
    """Run the real workspace reads against *repository*: the application has no bound workspace.

    The check's own probes (``requested_output_states``, ``undeclared_references``) are the
    production functions, given the real adapter, a real metadata capture and the real task-start
    base.
    """

    adapter = GitChangeCaptureAdapter()
    source = CheckWorkspaceSource(os.fspath(repository), "hmac-sha256:" + "0" * 64)
    real_states = check_change.requested_output_states
    real_references = check_change.undeclared_references

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
    named: tuple[str, ...] = (),
) -> tuple[StartInternalResult, Any]:
    """The cracker delivered and claimed with only the cracker declared, then one check.

    ``named`` are further values the agent's own action names in ``attempted_items`` (it says it
    worked on those exact paths), without declaring them.
    """

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
                "attempted_items": list[JsonValue](sorted({*delivered, *named}, key=str.encode)),
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


_OMITTED = {
    "category": "repository_excerpt",
    "omitted": True,
    "reason": "local_disclosure_not_authorized",
}


def _assert_withheld_with_continuation(projected: Mapping[str, JsonValue]) -> None:
    (row,) = _rows(projected)
    assert row["obligation_id"] == _OBLIGATION
    assert row["total"] == "2"
    assert row["paths"] == [_OMITTED, _OMITTED]
    text = _gate_text(projected)
    assert f"{_OBLIGATION} item 0 names (path withheld) and (path withheld)." in text
    assert "FinishUP returns only a name you published yourself" in text
    assert "`git status --porcelain --untracked-files=all`" in text
    assert "or their directory" in text
    for model in _MODELS:
        assert model.rsplit("/", 1)[1] not in str(projected)
        assert model.rsplit("/", 1)[1] not in text


async def test_biped_private_ceiling_withholds_names_no_record_attributes_to_the_agent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Files that appeared during the task through a shell or another process: nothing in the
    record ties them to the agent, so the names stay withheld with the typed continuation."""

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
    assert internal.leaf_authorship == ()
    _assert_withheld_with_continuation(projected)
    subject = _projection_subject(app, projected)
    assert DisclosureProvenance.SELF_AUTHORED not in subject.provenance


@pytest.mark.parametrize("words", ["prestaged", "ignored"])
async def test_a_pre_staged_or_force_added_ignored_file_is_never_named(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, words: str
) -> None:
    """Checker reproductions (#1): a file staged before the task (absent from HEAD and from the
    untracked listing) and an ignored file force-added later both appear as additions; neither
    is the agent's creation, and neither name returns."""

    repository, base = _workspace(tmp_path, words=words)
    _bind_workspace(monkeypatch, repository, base)
    app, _policy = await build_projection_application(seed=9200)
    started, _checked = await _run(app, 9200)
    _internal, projected = await _projected_status(app, started, 9250)
    _assert_withheld_with_continuation(projected)


async def test_a_name_returns_only_to_the_writer_and_session_that_published_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The agent named ``artifacts/english_ngrams.npz`` in its own action: that exact name comes
    back to it (it wrote that text), the other stays withheld; a later session or another writer
    of the same task does not get it."""

    repository, base = _workspace(tmp_path)
    _bind_workspace(monkeypatch, repository, base)
    app, _policy = await build_projection_application(seed=9300)
    started, _checked = await _run(app, 9300, named=("/app/" + _MODELS[0],))

    internal, projected = await _projected_status(app, started, 9350)
    (row,) = _rows(projected)
    assert row["paths"] == [_MODELS[0], _OMITTED]
    (leaf,) = internal.leaf_authorship
    assert leaf.item_pointer == "/closure_readiness/undeclared_references/0/paths/0"
    subject = _projection_subject(app, projected)
    assert DisclosureProvenance.SELF_AUTHORED in subject.provenance
    text = _gate_text(projected)
    assert '"artifacts/english_ngrams.npz" and (path withheld)' in text
    assert "`git status --porcelain --untracked-files=all`" in text

    # Another session (an attach mints a new session and writer) holds no authorship of it.
    attached = await app.start(start_request(9360, title="Vigenere cracker", refs=True))
    assert type(attached) is StartInternalResult
    assert attached.outcome == "attached"
    assert attached.writer_id != started.writer_id
    _internal, successor = await _projected_status(app, attached, 9370)
    _assert_withheld_with_continuation(successor)


@pytest.mark.parametrize("target", ["event", "object"])
async def test_redacting_the_publication_revokes_the_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, target: str
) -> None:
    """Checker reproduction (R2 #1): once the action that spelled the name is redacted, by its
    event ID or by its payload object ID, the name no longer returns; the loaded envelope keeps
    its original redaction state, so the status read must apply the effective redaction."""

    repository, base = _workspace(tmp_path)
    _bind_workspace(monkeypatch, repository, base)
    app, _policy = await build_projection_application(seed=9500)
    started, _checked = await _run(app, 9500, named=(_MODELS[0],))
    internal, projected = await _projected_status(app, started, 9550)
    assert _rows(projected)[0]["paths"] == [_MODELS[0], _OMITTED]

    ledger, _objects = readback._ledger(app, started.task_id)
    records = [row async for row in ledger.load_events(started.session_id)]
    (action,) = [row for row in records if str(row.event_id) == protocol_id("evt_", 9504)]
    payload = RedactionRecordedPayload(
        target_event_ids=(action.event_id,) if target == "event" else (),
        target_object_ids=(action.payload_ref.object_id,) if target == "object" else (),
        method=next(iter(RedactionMethod)),
        reason_category=next(iter(RedactionReasonCategory)),
        authority=actor_id("local-human"),
        remaining_gap="redacted_name_publication",
    )
    draft = EventDraft(
        event_id(protocol_id("evt_", 9601)),
        EventSchema("redaction_recorded", "1.0.0"),
        timestamp_from_datetime(datetime(2026, 10, 13, 12, tzinfo=UTC)),
        (),
        payload,
        payload.target_object_ids,
        (),
    )
    frontier = await readback._append(
        app,
        started,
        seed=9600,
        expected_frontier=internal.result_frontier.sequence,
        writer=started.writer_id,
        author=readback._agent_actor("redaction-test"),
        channel=PublicationChannel.COOPERATIVE_MCP,
        drafts=((draft, canonical_encode(encode_payload(payload))),),
    )
    checked = await app.check(
        CheckRequest.model_validate(
            {
                **request_base(protocol_id("req_", 9610)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": frontier_json(frontier),
                "mode": "deterministic_only",
            }
        )
    )
    assert type(checked) is CheckCommitResult
    internal, projected = await _projected_status(app, started, 9650)
    assert internal.leaf_authorship == ()
    _assert_withheld_with_continuation(projected)


async def test_an_owner_who_granted_repository_excerpts_sees_every_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, base = _workspace(tmp_path, words="prestaged")
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
    # The 18 copies named only by an ambiguous file name are disclosed, counted, never named.
    assert _AMBIGUOUS in checked.coverage.known_gaps
    assert checked.overall_next is None or _OBLIGATION not in checked.overall_next.target_refs

    internal, projected = await _projected_status(app, started, 9550)
    readiness = internal.closure_readiness
    assert _CODE not in (readiness.agent_actionable or ())
    assert _CODE not in (readiness.standing_limitations or ())
    assert _AMBIGUOUS in (readiness.standing_limitations or ())
    assert _AMBIGUOUS not in (readiness.agent_actionable or ())
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
    rendered = str(receipt.as_json())
    assert _CODE not in rendered
    assert "Files named ambiguously: 18." in rendered
    assert "case_0" not in rendered
