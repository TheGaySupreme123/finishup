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
    ReceiptSuccessModel,
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
    receipt_case, receipt = await _receipt_case(app, started, internal, 9555, "markdown")
    before = await project_case(app, receipt_case, 9556)
    assert _MODELS[0] in cast(str, before["human_text"])

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
        expected_frontier=receipt.result_frontier.sequence,
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
    replayed = await app.receipt(ReceiptRequest.model_validate(receipt_case.request_body))
    assert replayed.receipt_digest == receipt.receipt_digest
    after = await project_case(
        app,
        ProjectionCase("receipt", ControlMethod.RECEIPT, receipt_case.request_body, replayed),
        9652,
    )
    _assert_receipt_names_withheld(after, "markdown")


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


# tb4n5 privacy (CHECK_FIX_DELIVERY_R2 #2): a ``full_local`` receipt names the undeclared files in
# its prose, and that prose is classified ``finding_summary``, which the private default releases
# to agents. The receipt is not a trusted-human sink and the profile is not a repository-excerpt
# grant, so an agent must not read through it the names status withholds.


async def _receipt_case(
    app: Application,
    started: StartInternalResult,
    status: StatusInternalResult,
    seed: int,
    fmt: str,
    profile: str = "full_local",
) -> tuple[ProjectionCase, Any]:
    body: dict[str, JsonValue] = {
        **request_base(protocol_id("req_", seed)),
        "task_id": started.task_id,
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": frontier_json(status.result_frontier),
        "format": fmt,
        "include": "full",
        "redaction_profile": profile,
    }
    receipt = await app.receipt(ReceiptRequest.model_validate(body))
    return ProjectionCase("receipt", ControlMethod.RECEIPT, body, receipt), receipt


def _assert_receipt_names_withheld(projected: Mapping[str, JsonValue], fmt: str) -> None:
    text = canonical_encode(cast(JsonValue, projected)).decode()
    for model in _MODELS:
        assert model not in text
        assert model.rsplit("/", 1)[1] not in text
    privacy = cast(Mapping[str, Any], projected["privacy_projection"])
    assert privacy["sink"] == "agent_context"
    assert "repository_excerpt" in privacy["blocked_categories"]
    # Coverage-bounded: the leaf that named the files is listed, and its text says so.
    assert privacy["omitted_pointers"]
    prose = (
        projected["human_text"]
        if fmt != "json"
        else canonical_encode(projected["document"]).decode()
    )
    assert type(prose) is str
    assert "(receipt prose withheld: repository_excerpt)" in prose
    if fmt == "json":
        assert all(pointer.startswith("/document/") for pointer in privacy["omitted_pointers"])
    else:
        assert privacy["omitted_pointers"] == ["/human_text"]


@pytest.mark.parametrize(
    "client_kind,render_mode,tty",
    [
        ("mcp_bridge", "machine_readable", False),
        ("mcp_bridge", "human_readable", True),
        ("cli", "machine_readable", True),
        ("cli", "human_readable", False),
        ("ui", "machine_readable", False),
        # r3 F1: a forged or merely true terminal presentation is never owner authority.
        ("cli", "human_readable", True),
        ("ui", "human_readable", True),
    ],
)
@pytest.mark.parametrize("fmt", ["json", "markdown", "text"])
async def test_a_full_local_receipt_projected_to_an_agent_withholds_the_names(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fmt: str,
    client_kind: str,
    render_mode: str,
    tty: bool,
) -> None:
    from finishup.application.service import ClientProjectionContext
    from finishup.cli.render import render_human_receipt
    from finishup.mcp.server import result_from_public_model
    from finishup.mcp.summaries import summary_for_receipt
    from finishup.ports.control import ControlClientKind, McpHostProfile, ProjectionRenderMode
    from finishup.protocol.models import ReceiptResult

    context = ClientProjectionContext(
        ControlClientKind(client_kind), ProjectionRenderMode(render_mode), tty
    )
    repository, base = _workspace(tmp_path)
    _bind_workspace(monkeypatch, repository, base)
    app, _policy = await build_projection_application(seed=19800)
    started, _checked = await _run(app, 19800)
    status, projected_status = await _projected_status(app, started, 19850)
    _assert_withheld_with_continuation(projected_status)
    case, receipt = await _receipt_case(app, started, status, 19860, fmt)
    # The owner's stored receipt keeps the names (full detail, local only).
    local = canonical_encode(cast(JsonValue, receipt.as_json())).decode()
    assert all(model in local for model in _MODELS)
    projected = await project_case(app, case, 19861, context=context)
    _assert_receipt_names_withheld(projected, fmt)
    model = ReceiptResult.model_validate(projected)
    assert model.root.ok is True
    assert isinstance(model.root, ReceiptSuccessModel)
    for path in _MODELS:
        assert path not in summary_for_receipt(projected)
        assert path not in render_human_receipt(model.root)
    for host in ("codex", "claude", "cursor"):
        tool_result = result_from_public_model(model, host_profile=cast(McpHostProfile, host))
        rendered = tool_result.model_dump_json()
        assert all(path not in rendered for path in _MODELS)
        assert all(path.rsplit("/", 1)[1] not in rendered for path in _MODELS)
    # The structured coverage and gap identity survive the prose withholding.
    assert projected["coverage"] == receipt.as_json()["coverage"]
    if fmt == "json":
        from finishup.domain.receipts import receipt_document_from_json

        receipt_document_from_json(projected["document"])
    # The digest still names the stored owner receipt; nothing about it was rewritten.
    assert projected["receipt_digest"] == receipt.receipt_digest

    # The same request replays the stored receipt through the ledger read path (the one an
    # earlier build's stored receipt takes), and the replay is held to the same ceiling.
    replayed = await app.receipt(ReceiptRequest.model_validate(case.request_body))
    assert replayed.receipt_digest == receipt.receipt_digest
    _assert_receipt_names_withheld(
        await project_case(
            app,
            ProjectionCase("receipt", ControlMethod.RECEIPT, case.request_body, replayed),
            19871,
            context=context,
        ),
        fmt,
    )


@pytest.mark.parametrize("surface", ["cli", "cli_pty_facts", "cli_json_output", "tui"])
@pytest.mark.parametrize("fmt", ["json", "markdown", "text"])
async def test_ordinary_cli_and_tui_receipts_are_agent_facing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    surface: str,
    fmt: str,
) -> None:
    """r3 F1: without a ceremony grant every CLI and TUI receipt is the agent projection.

    The client context is the one the real command builds; even a context that claims a
    human-readable controlling terminal (what a pseudo-terminal produces) stays agent-facing.
    """

    import finishup.cli.app as cli_app
    from finishup.application.service import ClientProjectionContext
    from finishup.ports.control import ControlClientKind, ProjectionRenderMode
    from finishup.protocol.models import ReceiptResultModel
    from finishup.tui.runtime import FinishUpRuntime, _WorkSession

    repository, base = _workspace(tmp_path)
    _bind_workspace(monkeypatch, repository, base)
    app, _policy = await build_projection_application(seed=20700)
    started, _checked = await _run(app, 20700)
    status, _projected = await _projected_status(app, started, 20750)
    case, _receipt = await _receipt_case(app, started, status, 20760, fmt)
    sinks: list[str] = []
    delivered: list[str] = []

    class Client:
        def __init__(self, context: ClientProjectionContext) -> None:
            self.context = context

        async def receipt(self, request: Any, **_kwargs: object) -> ReceiptResultModel:
            body = {**case.request_body, **request.model_dump(mode="json", exclude_none=True)}
            projected = await project_case(
                app,
                ProjectionCase("receipt", ControlMethod.RECEIPT, case.request_body, case.internal)
                if surface != "tui"
                else ProjectionCase(
                    "receipt",
                    ControlMethod.RECEIPT,
                    body,
                    await app.receipt(ReceiptRequest.model_validate(body)),
                ),
                20761,
                context=self.context,
            )
            sinks.append(cast(Mapping[str, Any], projected["privacy_projection"])["sink"])
            delivered.append(canonical_encode(cast(JsonValue, projected)).decode())
            return ReceiptResultModel.model_validate(projected)

        async def close(self) -> None:
            pass

    async def build(
        client_kind: ControlClientKind = ControlClientKind.CLI,
        *,
        projection_render_mode: ProjectionRenderMode = ProjectionRenderMode.MACHINE_READABLE,
        output_is_controlling_tty: bool = False,
        **_kwargs: object,
    ) -> Client:
        if surface == "cli_pty_facts":
            # What a hello from inside an agent's pseudo-terminal can claim.
            projection_render_mode = ProjectionRenderMode.HUMAN_READABLE
            output_is_controlling_tty = True
        return Client(
            ClientProjectionContext(client_kind, projection_render_mode, output_is_controlling_tty)
        )

    monkeypatch.setattr(cli_app, "build_service_client", build)
    if surface == "tui":
        runtime = FinishUpRuntime(cwd=repository)
        runtime._sessions["owner"] = _WorkSession(
            started.task_id, started.session_id, started.writer_id, status.result_frontier
        )
        shown = "\n".join((await runtime.build_receipt("owner", fmt)).rendered_lines)
    else:
        assert (
            await cli_app._call_workflow(
                "receipt",
                ReceiptRequest,
                None,
                canonical_encode(case.request_body).decode(),
                surface == "cli_json_output",
                None,
            )
            == 0
        )
        shown = capsys.readouterr().out
    assert sinks == ["agent_context"]
    assert not any(path in delivered[0] for path in _MODELS)
    assert not any(path in shown for path in _MODELS)


async def test_owner_view_request_runs_the_ceremony_on_its_own_connection_first(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """``--owner-view`` binds the ceremony to this request and this client's connection, and
    sends the receipt call only after the ceremony succeeded; a refusal sends nothing."""

    import finishup.cli.app as cli_app
    import finishup.cli.unlock as unlock
    from finishup.protocol.models import ReceiptResultModel
    from finishup.service.confidential_client import ConfidentialClientError
    from finishup.service.owner_view import owner_receipt_view_target

    repository, base = _workspace(tmp_path)
    _bind_workspace(monkeypatch, repository, base)
    app, _policy = await build_projection_application(seed=20770)
    started, _checked = await _run(app, 20770)
    status, _projected = await _projected_status(app, started, 20775)
    case, _receipt = await _receipt_case(app, started, status, 20780, "markdown")
    nonce = "a" * 64
    calls: list[str] = []

    class Client:
        def owner_receipt_view_target(self, request: Any) -> Any:
            return owner_receipt_view_target(request, nonce)

        async def receipt(self, _request: object, **_kwargs: object) -> ReceiptResultModel:
            calls.append("receipt")
            projected = await project_case(app, case, 20781)
            return ReceiptResultModel.model_validate(projected)

        async def close(self) -> None:
            pass

    async def build(*_args: object, **_kwargs: object) -> Client:
        return Client()

    ceremonies: list[Any] = []

    async def refuse(target: Any, **_kwargs: Any) -> Any:
        ceremonies.append(target)
        raise ConfidentialClientError("reauthentication_unavailable")

    monkeypatch.setattr(cli_app, "build_service_client", build)
    monkeypatch.setattr(unlock, "authorize_owner_receipt_view", refuse)
    code = await cli_app._call_workflow(
        "receipt",
        ReceiptRequest,
        None,
        canonical_encode(case.request_body).decode(),
        False,
        None,
        owner_view=True,
    )
    assert code != 0
    assert calls == []
    captured = capsys.readouterr()
    assert "owner_view_unavailable" in captured.err
    assert "git status --short" in captured.err
    assert all(path not in captured.out + captured.err for path in _MODELS)
    request = ReceiptRequest.model_validate(case.request_body)
    assert ceremonies == [owner_receipt_view_target(request, nonce)]

    async def grant(target: Any, **_kwargs: Any) -> Any:
        ceremonies.append(target)
        calls.append("ceremony")

    monkeypatch.setattr(unlock, "authorize_owner_receipt_view", grant)
    code = await cli_app._call_workflow(
        "receipt",
        ReceiptRequest,
        None,
        canonical_encode(case.request_body).decode(),
        False,
        None,
        owner_view=True,
    )
    assert code == 0
    assert calls == ["ceremony", "receipt"]


async def test_receipt_name_provenance_is_per_name_and_auditable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, base = _workspace(tmp_path)
    _bind_workspace(monkeypatch, repository, base)
    app, _policy = await build_projection_application(seed=20800)
    started, _checked = await _run(app, 20800, named=(_MODELS[0],))
    status, _projected = await _projected_status(app, started, 20850)
    case, receipt = await _receipt_case(app, started, status, 20860, "markdown")
    projected = await project_case(app, case, 20861)
    text = cast(str, projected["human_text"])
    assert _MODELS[0] in text
    assert _MODELS[1] not in text
    assert "Summary" in text and "(receipt prose withheld: repository_excerpt)" in text
    assert receipt.human_text != text
    subject = _projection_subject(app, projected)
    denied = [
        pointer for pointer, _category, allowed, _reason in subject.field_decisions if not allowed
    ]
    assert denied == ["/human_text/@repository_name/1"]
    assert cast(Mapping[str, Any], projected["privacy_projection"])["omitted_pointers"] == [
        "/human_text"
    ]


@pytest.mark.parametrize("fmt", ["json", "markdown", "text"])
async def test_the_owner_local_view_and_a_granted_policy_keep_the_receipt_names(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fmt: str
) -> None:
    from finishup.application.service import ClientProjectionContext
    from finishup.ports.control import ControlClientKind, ProjectionRenderMode

    repository, base = _workspace(tmp_path)
    _bind_workspace(monkeypatch, repository, base)
    app, _policy = await build_projection_application(seed=19900)
    started, _checked = await _run(app, 19900)
    status, _projected = await _projected_status(app, started, 19950)
    case, _receipt = await _receipt_case(app, started, status, 19960, fmt)
    human = await project_case(
        app,
        case,
        19961,
        # The service sets ``owner_view`` only after consuming a ceremony grant.
        context=ClientProjectionContext(
            ControlClientKind.CLI, ProjectionRenderMode.HUMAN_READABLE, False, owner_view=True
        ),
    )
    assert cast(Mapping[str, Any], human["privacy_projection"])["sink"] == "local_human_view"
    text = canonical_encode(cast(JsonValue, human)).decode()
    assert all(model in text for model in _MODELS)

    def granted(policy: PrivacyPolicy) -> PrivacyPolicy:
        return replace(
            policy,
            agent_context_categories=(
                *policy.agent_context_categories,
                DataCategory.REPOSITORY_EXCERPT,
            ),
        )

    (tmp_path / "granted").mkdir()
    repository, base = _workspace(tmp_path / "granted")
    _bind_workspace(monkeypatch, repository, base)
    app, _policy = await build_projection_application(seed=20000, policy_transform=granted)
    started, _checked = await _run(app, 20000)
    status, _projected = await _projected_status(app, started, 20050)
    case, _receipt = await _receipt_case(app, started, status, 20060, fmt)
    projected = await project_case(app, case, 20061)
    privacy = cast(Mapping[str, Any], projected["privacy_projection"])
    assert privacy["omitted_pointers"] == []
    text = canonical_encode(cast(JsonValue, projected)).decode()
    assert all(model in text for model in _MODELS)


async def test_receipt_prose_of_any_category_cannot_carry_a_name_to_an_agent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Obligation and section prose obey the excerpt ceiling, including a bare basename; only
    the name spans are withheld, never the sentence around them."""

    repository, base = _workspace(tmp_path)
    _bind_workspace(monkeypatch, repository, base)
    app, _policy = await build_projection_application(seed=20100)
    started, _checked = await _run(app, 20100)
    status, _projected = await _projected_status(app, started, 20150)
    case, receipt = await _receipt_case(app, started, status, 20160, "json", "default_local_export")
    document = cast(dict[str, Any], receipt.document)
    assert not any(model in canonical_encode(document).decode() for model in _MODELS)
    document["obligations"][0]["summary"] = f"Loads {_MODELS[1]} at start."
    body = document["sections"][0]["body"]
    document["sections"][0]["body"] = body + " It also reads english_ngrams.npz."
    projected = await project_case(
        app, ProjectionCase("receipt", ControlMethod.RECEIPT, case.request_body, receipt), 20161
    )
    text = canonical_encode(cast(JsonValue, projected)).decode()
    assert "english_ngrams" not in text and "english_words" not in text
    projected_document = cast(Mapping[str, Any], projected["document"])
    token = "(receipt prose withheld: repository_excerpt)"
    assert projected_document["obligations"][0]["summary"] == f"Loads {token} at start."
    assert projected_document["sections"][0]["body"] == body + f" It also reads {token}."
    privacy = cast(Mapping[str, Any], projected["privacy_projection"])
    assert "/document/obligations/0/summary" in privacy["omitted_pointers"]
    assert "/document/sections/0/body" in privacy["omitted_pointers"]


async def test_excerpt_grant_does_not_grant_a_denied_receipt_prose_category(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The additional excerpt gate never grants a denied ordinary prose category."""

    def no_prose(policy: PrivacyPolicy) -> PrivacyPolicy:
        return replace(
            policy,
            agent_context_categories=(
                *(
                    category
                    for category in policy.agent_context_categories
                    if category is not DataCategory.FINDING_SUMMARY
                ),
                DataCategory.REPOSITORY_EXCERPT,
            ),
        )

    repository, base = _workspace(tmp_path)
    _bind_workspace(monkeypatch, repository, base)
    app, _policy = await build_projection_application(seed=20200, policy_transform=no_prose)
    started, _checked = await _run(app, 20200)
    status, _projected = await _projected_status(app, started, 20250)
    case, _receipt = await _receipt_case(app, started, status, 20260, "markdown")
    projected = await project_case(app, case, 20261)
    assert projected["human_text"] == {
        "category": "finding_summary",
        "omitted": True,
        "reason": "local_disclosure_not_authorized",
    }
    privacy = cast(Mapping[str, Any], projected["privacy_projection"])
    assert privacy["omitted_pointers"] == ["/human_text"]


@pytest.mark.parametrize("fmt", ["json", "markdown", "text"])
async def test_receipt_prose_around_a_withheld_name_stays_visible(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fmt: str
) -> None:
    """r2 (item 1): the r1 gate blanked every prose string; only the name span is withheld."""

    repository, base = _workspace(tmp_path)
    _bind_workspace(monkeypatch, repository, base)
    app, _policy = await build_projection_application(seed=20300)
    started, _checked = await _run(app, 20300)
    status, _projected = await _projected_status(app, started, 20350)
    case, receipt = await _receipt_case(app, started, status, 20360, fmt)
    stored = canonical_encode(
        cast(JsonValue, receipt.document if fmt == "json" else receipt.human_text)
    ).decode()
    assert all(model in stored for model in _MODELS)
    projected = await project_case(app, case, 20361)
    _assert_receipt_names_withheld(projected, fmt)
    if fmt == "json":
        document = cast(Mapping[str, Any], projected["document"])
        stored_document = cast(Mapping[str, Any], receipt.document)
        # Every section title and every prose string that names no file is unchanged.
        for shown, kept in zip(document["sections"], stored_document["sections"], strict=True):
            assert shown["title"] == kept["title"]
        unchanged = [
            leaf
            for leaf in _string_leaves(stored_document)
            if not any(model in leaf for model in _MODELS)
        ]
        assert unchanged and set(unchanged) <= set(_string_leaves(document))
    else:
        text = cast(str, projected["human_text"])
        kept_lines = [
            line
            for line in cast(str, receipt.human_text).splitlines()
            if not any(model in line for model in _MODELS)
        ]
        assert kept_lines and all(line in text.splitlines() for line in kept_lines)
        withheld = [line for line in text.splitlines() if "(receipt prose withheld" in line]
        # The sentence naming the files keeps its words; only the names became the token.
        assert withheld and all(len(line) > len("(receipt prose withheld: x)") for line in withheld)


def _string_leaves(value: object) -> list[str]:
    if isinstance(value, Mapping):
        children: list[object] = list(cast(Mapping[str, object], value).values())
    elif isinstance(value, (list, tuple)):
        children = list(cast(Sequence[object], value))
    else:
        return [value] if type(value) is str else []
    return [leaf for child in children for leaf in _string_leaves(child)]


async def test_withheld_receipt_content_is_absent_from_the_authorized_sink_payload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import base64

    from finishup.adapters.privacy.local_enforcer import LocalPrivacyEnforcer
    from finishup.domain.privacy import ClassifiedContext, PrivacyDecision
    from finishup.ports.privacy import MinimizedDisclosure
    from finishup.protocol.canonical import strict_json_parse

    repository, base = _workspace(tmp_path)
    _bind_workspace(monkeypatch, repository, base)
    app, _policy = await build_projection_application(seed=20400)
    started, _checked = await _run(app, 20400)
    status, _projected = await _projected_status(app, started, 20450)
    case, _receipt = await _receipt_case(app, started, status, 20460, "json")
    payloads: list[bytes] = []
    original = LocalPrivacyEnforcer.minimize_and_scan

    def capture(
        self: LocalPrivacyEnforcer, classified: ClassifiedContext, decision: PrivacyDecision
    ) -> MinimizedDisclosure:
        minimized = original(self, classified, decision)
        payloads.append(minimized.prepared_bytes)
        return minimized

    monkeypatch.setattr(LocalPrivacyEnforcer, "minimize_and_scan", capture)
    projected = await project_case(app, case, 20461)
    _assert_receipt_names_withheld(projected, "json")
    assert payloads
    for payload in payloads:
        body = cast(Mapping[str, Any], strict_json_parse(payload))
        content = b"\n".join(base64.b64decode(item["content_base64"]) for item in body["items"])
        assert all(path.encode() not in content for path in _MODELS)


@pytest.mark.parametrize("fmt", ["json", "markdown", "text"])
async def test_clean_receipt_keeps_normal_agent_prose(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fmt: str
) -> None:
    repository, base = _workspace(tmp_path)
    _bind_workspace(monkeypatch, repository, base)
    app, _policy = await build_projection_application(seed=20500)
    started, _checked = await _run(app, 20500, delivered=(_CRACKER, *_MODELS), expect_gap=False)
    status, _projected = await _projected_status(app, started, 20550)
    case, receipt = await _receipt_case(app, started, status, 20560, fmt, "default_local_export")
    projected = await project_case(app, case, 20561)
    assert projected["human_text"] == receipt.human_text
    assert projected["document"] == receipt.document
    assert cast(Mapping[str, Any], projected["privacy_projection"])["omitted_pointers"] == []


async def test_large_receipt_coalesces_omissions_without_losing_coverage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Hundreds of prose leaves that spell a withheld name still project (r1 review item 3).

    Each leaf is its own omission; past the 512-pointer wire bound the list coalesces to the
    containing fields instead of failing with ``projection_pointer_limit``. Only the name spans
    are withheld: every leaf keeps its own surrounding words.
    """

    repository, base = _workspace(tmp_path)
    _bind_workspace(monkeypatch, repository, base)
    app, _policy = await build_projection_application(seed=20600)
    started, _checked = await _run(app, 20600)
    status, _projected = await _projected_status(app, started, 20650)
    case, receipt = await _receipt_case(app, started, status, 20660, "json")
    document = cast(dict[str, Any], receipt.document)
    import copy

    # Fill the document to its schema bounds with prose that spells a withheld name: 64 items
    # in each section, 100 obligation summaries and 64 gap details, each leaf its own omission.
    for section_index, section in enumerate(document["sections"]):
        section["items"] = [
            f'Row {section_index}.{n} loads "{_MODELS[n % 2]}" before the solver.'
            for n in range(64)
        ]
    template = document["obligations"][0]
    document["obligations"] = [
        {
            **copy.deepcopy(template),
            "obligation_id": protocol_id("obl_", 60000 + n),
            "summary": f"Obligation {n} reads {_MODELS[n % 2]} once.",
        }
        for n in range(100)
    ]
    gap = next(gap for gap in document["gaps"] if gap.get("detail"))
    document["gaps"] = [
        {**copy.deepcopy(gap), "detail": f"Gap {n} names {_MODELS[n % 2]}."} for n in range(64)
    ]
    leaf_count = 64 * len(document["sections"]) + 100 + 64
    assert leaf_count > 512
    projected = await project_case(app, case, 20661)
    pointers = cast(Mapping[str, Any], projected["privacy_projection"])["omitted_pointers"]
    assert 0 < len(pointers) <= 512
    subject = _projection_subject(app, projected)
    assert subject.omitted_count >= leaf_count
    denied = [
        pointer for pointer, _category, allowed, _reason in subject.field_decisions if not allowed
    ]
    for origin in denied:
        leaf = origin.split("/@repository_name/", 1)[0]
        assert any(leaf == pointer or leaf.startswith(pointer + "/") for pointer in pointers)
    encoded = canonical_encode(projected).decode()
    assert all(model not in encoded for model in _MODELS)
    projected_sections = cast(Mapping[str, Any], projected["document"])["sections"]
    assert projected_sections[0]["items"][3] == (
        "Row 0.3 loads (receipt prose withheld: repository_excerpt) before the solver."
    )
    assert projected["coverage"] == receipt.as_json()["coverage"]
    assert projected["receipt_digest"] == receipt.receipt_digest


@pytest.mark.parametrize("fmt", ["json", "markdown", "text"])
async def test_a_repository_name_cannot_withhold_fixed_receipt_headings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fmt: str
) -> None:
    repository, base = _workspace(tmp_path)
    (repository / _MODELS[0]).rename(repository / "artifacts/Summary")
    (repository / _CRACKER).write_text(_LOADER.replace("english_ngrams.npz", "Summary"))
    _bind_workspace(monkeypatch, repository, base)
    app, _policy = await build_projection_application(seed=20900)
    started, _checked = await _run(app, 20900)
    status, _projected = await _projected_status(app, started, 20950)
    case, _receipt = await _receipt_case(app, started, status, 20960, fmt)
    projected = await project_case(app, case, 20961)
    if fmt == "json":
        assert cast(Mapping[str, Any], projected["document"])["sections"][0]["title"] == "Summary"
    else:
        heading = "## Summary" if fmt == "markdown" else "Summary"
        assert cast(str, projected["human_text"]).startswith(heading + "\n")
    assert "artifacts/Summary" not in canonical_encode(projected).decode()


async def test_dot_slash_spellings_in_receipt_prose_are_withheld(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """r3 F2: the reviewer's ``./`` repro through the production projection."""

    # A real repository under a directory whose name has a space (R3-F2).
    spaced = tmp_path / "My Project"
    spaced.mkdir(mode=0o700)
    repository, base = _workspace(spaced)
    _bind_workspace(monkeypatch, repository, base)
    app, _policy = await build_projection_application(seed=21000)
    started, _checked = await _run(app, 21000)
    status, _projected = await _projected_status(app, started, 21050)
    case, receipt = await _receipt_case(app, started, status, 21060, "json", "default_local_export")
    document = cast(dict[str, Any], receipt.document)
    document["obligations"][0]["summary"] = "Loads ./artifacts/english_words.npz at start."
    body = document["sections"][0]["body"]
    document["sections"][0]["body"] = body + ' It also reads "./artifacts/english_ngrams.npz".'
    # R3-F2: an absolute spelling through a directory with spaces, single-quoted.
    absolute = f"'{repository}/artifacts/english_words.npz'"
    document["sections"][0]["coverage_note"] = f"Checked {absolute} too."
    projected = await project_case(app, case, 21061)
    text = canonical_encode(cast(JsonValue, projected)).decode()
    assert "english_ngrams" not in text and "english_words" not in text
    token = "(receipt prose withheld: repository_excerpt)"
    projected_document = cast(Mapping[str, Any], projected["document"])
    assert projected_document["obligations"][0]["summary"] == f"Loads {token} at start."
    assert projected_document["sections"][0]["body"] == body + f" It also reads {token}."
    assert projected_document["sections"][0]["coverage_note"] == f"Checked {token} too."
    privacy = cast(Mapping[str, Any], projected["privacy_projection"])
    assert "/document/obligations/0/summary" in privacy["omitted_pointers"]
    assert "/document/sections/0/coverage_note" in privacy["omitted_pointers"]


@pytest.mark.parametrize("quote", ["`", '"', "'"])
async def test_a_published_name_cannot_carry_an_unpublished_one_out_of_a_quoted_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, quote: str
) -> None:
    """#1073 review round 3, T1: the requester published english_ngrams.npz; a quoted command
    naming english_words.npz before it must still withhold english_words.npz."""

    repository, base = _workspace(tmp_path)
    _bind_workspace(monkeypatch, repository, base)
    app, _policy = await build_projection_application(seed=32000)
    started, _checked = await _run(app, 32000, named=("/app/" + _MODELS[0],))
    status, _projected = await _projected_status(app, started, 32050)
    case, receipt = await _receipt_case(app, started, status, 32060, "json", "default_local_export")
    document = cast(dict[str, Any], receipt.document)
    command = (
        f"/usr/bin/cmp {repository}/artifacts/english_words.npz "
        f"{repository}/artifacts/english_ngrams.npz"
    )
    if quote == "'":
        command = "~/app/artifacts/english_words.npz ~/app/artifacts/english_ngrams.npz"
    document["obligations"][0]["summary"] = f"Ran {quote}{command}{quote} first."
    projected = await project_case(app, case, 32061)
    summary = cast(Mapping[str, Any], projected["document"])["obligations"][0]["summary"]
    assert "english_words" not in summary, summary
    assert "english_ngrams.npz" in summary, summary
    assert "(receipt prose withheld: repository_excerpt)" in summary
    privacy = cast(Mapping[str, Any], projected["privacy_projection"])
    assert "/document/obligations/0/summary" in privacy["omitted_pointers"]


_TOP_LEVEL_LOADER = """import os

import numpy as np

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TABLE = np.load(os.path.join(ROOT, "vocab_table"))
"""


async def test_a_top_level_extensionless_name_is_withheld_behind_any_path_prefix(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#1073 review P2-1: ``./vocab_table`` and ``/abs/repo/vocab_table`` in prose."""

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
    (repository / "artifacts").mkdir()
    base = GitChangeCaptureAdapter().read_task_base(os.fspath(repository))
    (repository / "artifacts" / "cracker.py").write_text(_TOP_LEVEL_LOADER, encoding="utf-8")
    (repository / "vocab_table").write_bytes(b"\x93NUMPY\x00\x01table")
    _bind_workspace(monkeypatch, repository, base)
    app, _policy = await build_projection_application(seed=31000)
    started, _checked = await _run(app, 31000)
    status, _projected = await _projected_status(app, started, 31050)
    case, receipt = await _receipt_case(app, started, status, 31060, "json", "default_local_export")
    document = cast(dict[str, Any], receipt.document)
    document["obligations"][0]["summary"] = "Loads ./vocab_table and .//vocab_table at start."
    document["sections"][0]["coverage_note"] = f"Checked {repository}//vocab_table too."
    body = document["sections"][0]["body"]
    # The quoted control proves the check recorded the undeclared top-level file.
    document["sections"][0]["body"] = (
        body + ' Control: "vocab_table". The vocab_table word alone stays.'
    )
    projected = await project_case(app, case, 31061)
    token = "(receipt prose withheld: repository_excerpt)"
    projected_document = cast(Mapping[str, Any], projected["document"])
    assert projected_document["obligations"][0]["summary"] == (
        f"Loads {token} and {token} at start."
    )
    assert projected_document["sections"][0]["coverage_note"] == f"Checked {token} too."
    privacy = cast(Mapping[str, Any], projected["privacy_projection"])
    assert "/document/obligations/0/summary" in privacy["omitted_pointers"]
    assert "/document/sections/0/coverage_note" in privacy["omitted_pointers"]
    text = canonical_encode(cast(JsonValue, projected)).decode()
    # Only the plain word the test appended survives; every path spelling of the name is gone.
    assert text.count("vocab_table") == 1
    assert projected_document["sections"][0]["body"] == (
        body + f" Control: {token}. The vocab_table word alone stays."
    )


@pytest.mark.parametrize("fmt", ["json", "markdown", "text"])
async def test_token_expansion_returns_a_bounded_valid_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fmt: str
) -> None:
    """r3 F3: short repeated names expanded by the token stay inside every bound.

    Before the fix the reviewer's 7,600-character ``human_text`` became 18,000 characters and
    the projection failed with ``invalid_privacy_value``. Now the presentation is cut visibly,
    every withheld token is whole, and the audit still holds one denial per name and field.
    """

    from dataclasses import replace as dc_replace

    from finishup.domain.privacy import MAX_EGRESS_ITEM_BYTES
    from finishup.protocol.models import ReceiptResultModel

    repository, base = _workspace(tmp_path)
    _bind_workspace(monkeypatch, repository, base)
    app, _policy = await build_projection_application(seed=21100)
    started, _checked = await _run(app, 21100)
    status, _projected = await _projected_status(app, started, 21150)
    case, receipt = await _receipt_case(app, started, status, 21160, fmt)
    names = "english_ngrams.npz " * 400
    if fmt == "json":
        document = cast(dict[str, Any], receipt.document)
        document["sections"][0]["body"] = names
        document["sections"][1]["items"] = [names[:8000]]
        source = receipt
    else:
        source = dc_replace(receipt, human_text=names)
    projected = await project_case(
        app, ProjectionCase("receipt", ControlMethod.RECEIPT, case.request_body, source), 21161
    )
    ReceiptResultModel.model_validate(projected)
    token = "(receipt prose withheld: repository_excerpt)"
    fields = (
        [
            cast(Mapping[str, Any], projected["document"])["sections"][0]["body"],
            cast(Mapping[str, Any], projected["document"])["sections"][1]["items"][0],
        ]
        if fmt == "json"
        else [cast(str, projected["human_text"])]
    )
    for shown in fields:
        assert "english_ngrams" not in shown
        assert len(canonical_encode(shown)) <= MAX_EGRESS_ITEM_BYTES
        kept, marker = shown.rsplit(" [receipt text truncated after withholding: ", 1)
        assert marker.endswith(" characters not shown]")
        assert kept.replace(token, "").strip() == ""
    subject = _projection_subject(app, projected)
    denied = [
        pointer for pointer, _category, allowed, _reason in subject.field_decisions if not allowed
    ]
    expected = (
        {"/document/sections/0/body", "/document/sections/1/items/0"}
        if fmt == "json"
        else {"/human_text"}
    )
    assert {origin.split("/@repository_name/", 1)[0] for origin in denied} >= expected
