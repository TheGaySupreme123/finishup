"""Durable check aggregate and status coverage must survive restart (issue #55 / plan 03).

A successful check used to leave ``p1_projection_state`` with null latest-check columns and
overwrite ``status_coverage_canonical`` with the engine-derived envelope's
``check_types: ["none"]``. The in-memory projection held the truth, so the lie was invisible
until the bundle was reopened or the durable row was read directly.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import apsw
import pytest

from builders.ledger_adapters import MemoryObjects
from builders.replay import replay_records
from integration.storage.test_append_and_replay import (
    command_from_records,
    file_sqlite_for,
    uuid_id,
)
from yoetz.adapters.sqlite.repository import SqliteLedger
from yoetz.domain.events import (
    EventDraft,
    EventPayload,
    FindingRecordedPayload,
    LedgerRecord,
    RedactionRecordedPayload,
    ResponseRecordedPayload,
    encode_payload,
)
from yoetz.domain.findings import CheckVerdict, Finding, RankedFindings
from yoetz.domain.values import (
    Frontier,
    event_id,
    finding_id,
    object_id,
    parse_rfc3339_millis,
)
from yoetz.ports.ledger import (
    AppendCommand,
    AppendEntry,
    CheckCommitResult,
    CheckPhase,
    CheckPolicyExecution,
    FrozenCase,
    OperationKind,
)
from yoetz.ports.objects import ObjectKind, ObjectMetadata, ObjectRef, ObjectSource
from yoetz.protocol.canonical import canonical_digest, canonical_encode, strict_json_parse
from yoetz.protocol.coverage import CheckType, Coverage
from yoetz.protocol.models import SemanticReason, SemanticStatus


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _projection_row(db: apsw.Connection) -> dict[str, Any]:
    columns = (
        "frontier_seq",
        "status_coverage_canonical",
        "status_gap_codes_canonical",
        "latest_check_event_id",
        "latest_subject_frontier_seq",
        "latest_subject_frontier_digest",
        "latest_verdict",
        "latest_returned_finding_ids",
        "latest_suppressed_count",
        "latest_coverage_canonical",
        "freshness",
        "unknown_event_count",
    )
    row = db.execute(
        "SELECT " + ",".join(columns) + " FROM p1_projection_state WHERE projection_name='work'"
    ).fetchone()
    assert row is not None
    return dict(zip(columns, row, strict=True))


def _decode_coverage(blob: bytes | None) -> dict[str, Any]:
    assert blob is not None
    parsed = strict_json_parse(blob)
    assert type(parsed) is dict
    return cast(dict[str, Any], parsed)


def _check_types(blob: bytes | None) -> list[str]:
    return list(cast(list[str], _decode_coverage(blob)["check_types"]))


async def _local_result_ref(objects: MemoryObjects, command: AppendCommand) -> ObjectRef:
    staged = await objects.stage(
        ObjectSource(data=b"{}", declared_size=2),
        ObjectMetadata(
            ObjectKind.DETERMINISTIC_RESULT,
            "application/vnd.yoetz.deterministic-result+json",
            command.task_id,
            command.entries[0].payload_object.metadata.created_at,
        ),
    )
    return await objects.finalize(staged)


def _checked_coverage(base: Coverage, *check_types: CheckType) -> Coverage:
    types = tuple(check_types) if check_types else (CheckType.DETERMINISTIC,)
    return replace(base, check_types=types)


async def _commit_check(
    ledger: SqliteLedger,
    command: AppendCommand,
    objects: MemoryObjects,
    subject_frontier: Frontier,
    *,
    request_number: int,
    coverage: Coverage,
    verdict: CheckVerdict = CheckVerdict.NO_ISSUE_DETECTED,
    suppressed_count: int = 0,
    semantic_status: SemanticStatus = SemanticStatus.NOT_REQUESTED,
    semantic_reason: SemanticReason = SemanticReason.DETERMINISTIC_MODE,
    findings: tuple[Finding, ...] = (),
    semantic_withheld_item_ids: tuple[str, ...] = (),
) -> CheckCommitResult:
    check_request = uuid_id("req", request_number)
    digest = "sha256:" + f"{request_number:064d}"[-64:]
    frozen = await ledger.freeze_case(
        command.session_id,
        command.writer_id,
        subject_frontier.sequence,
        check_request,
        digest,
    )
    assert type(frozen) is FrozenCase
    lease = await ledger.advance_check_phase(
        frozen.lease,
        CheckPhase.RESERVED,
        CheckPhase.LOCAL_READY,
        await _local_result_ref(objects, command),
    )
    lease = await ledger.advance_check_phase(
        lease,
        CheckPhase.LOCAL_READY,
        CheckPhase.READY_TO_FINALIZE,
    )
    ranked = RankedFindings(findings, suppressed_count, verdict, coverage)
    result = await ledger.commit_check_if_current(
        FrozenCase(frozen.case, lease),
        ranked,
        (CheckPolicyExecution("work-integrity", "0.1.0", "run", "completed"),),
        semantic_status,
        semantic_reason,
        None,
        check_request,
        semantic_withheld_item_ids=semantic_withheld_item_ids,
    )
    assert result.outcome == "committed"
    return result


@pytest.mark.anyio
async def test_check_totals_survive_reopen_and_idempotent_recovery(tmp_path: Path) -> None:
    """Recovery must use the frozen totals, never recount post-check work (#971)."""

    records = replay_records("projection-rebuild")[:1]
    command, objects = command_from_records(records)
    path = tmp_path / "check-totals.sqlite3"
    ledger, db = file_sqlite_for(command, objects, path)
    accepted = await ledger.append_batch(command)
    committed = await _commit_check(
        ledger,
        command,
        objects,
        accepted.result_frontier,
        request_number=91_971,
        coverage=_checked_coverage(command.entries[0].coverage),
        verdict=CheckVerdict.INSUFFICIENT_COVERAGE,
    )
    assert committed.totals is not None
    totals = cast(Mapping[str, Mapping[str, str]], committed.totals)
    assert totals["commands"]["observed"] == "0"
    assert totals["obligations"]["declared"] == "0"
    db.close()

    reopened, reopened_db = file_sqlite_for(command, objects, path)
    replayed = await reopened.freeze_case(
        command.session_id,
        command.writer_id,
        accepted.result_frontier.sequence,
        uuid_id("req", 91_971),
        "sha256:" + f"{91_971:064d}",
    )
    assert isinstance(replayed, CheckCommitResult)
    assert replayed.outcome == "replayed"
    assert replayed.totals == committed.totals
    reopened_db.close()


@pytest.mark.anyio
async def test_withheld_review_items_survive_reopen_and_idempotent_recovery(
    tmp_path: Path,
) -> None:
    """The SQLite replay rebuilt the check result without its withheld item ids (#982)."""

    records = replay_records("projection-rebuild")[:1]
    command, objects = command_from_records(records)
    path = tmp_path / "check-withheld.sqlite3"
    ledger, db = file_sqlite_for(command, objects, path)
    accepted = await ledger.append_batch(command)
    base = _checked_coverage(command.entries[0].coverage)
    committed = await _commit_check(
        ledger,
        command,
        objects,
        accepted.result_frontier,
        request_number=91_982,
        coverage=replace(
            base,
            known_gaps=tuple(
                sorted({*base.known_gaps, "semantic_review_item_withheld"}, key=str.encode)
            ),
        ),
        verdict=CheckVerdict.INSUFFICIENT_COVERAGE,
        semantic_withheld_item_ids=("excerpt-heuristic",),
    )
    assert committed.semantic_withheld_item_ids == ("excerpt-heuristic",)
    db.close()

    reopened, reopened_db = file_sqlite_for(command, objects, path)
    replayed = await reopened.freeze_case(
        command.session_id,
        command.writer_id,
        accepted.result_frontier.sequence,
        uuid_id("req", 91_982),
        "sha256:" + f"{91_982:064d}",
    )
    assert isinstance(replayed, CheckCommitResult)
    assert replayed.outcome == "replayed"
    assert replayed.semantic_withheld_item_ids == ("excerpt-heuristic",)
    reopened_db.close()


def _assert_check_aggregate_consistent(row: dict[str, Any], *, has_check: bool) -> None:
    """Honour 0001.sql null/non-null consistency over the latest-check columns."""

    fields = (
        row["latest_check_event_id"],
        row["latest_subject_frontier_seq"],
        row["latest_subject_frontier_digest"],
        row["latest_verdict"],
        row["latest_returned_finding_ids"],
        row["latest_suppressed_count"],
        row["latest_coverage_canonical"],
    )
    if has_check:
        assert all(value is not None for value in fields)
        assert row["latest_subject_frontier_seq"] <= row["frontier_seq"]
        assert row["latest_subject_frontier_seq"] > 0
        assert row["latest_subject_frontier_digest"] != "genesis"
    else:
        assert all(value is None for value in fields)


@pytest.mark.anyio
async def test_never_checked_task_reports_none_coverage(tmp_path: Path) -> None:
    records = replay_records("projection-rebuild")[:1]
    command, objects = command_from_records(records)
    path = tmp_path / "never-checked.sqlite3"
    ledger, db = file_sqlite_for(command, objects, path)
    await ledger.append_batch(command)

    row = _projection_row(db)
    assert _check_types(row["status_coverage_canonical"]) == ["none"]
    _assert_check_aggregate_consistent(row, has_check=False)
    db.close()

    _reopened, reopened_db = file_sqlite_for(command, objects, path)
    row = _projection_row(reopened_db)
    assert _check_types(row["status_coverage_canonical"]) == ["none"]
    _assert_check_aggregate_consistent(row, has_check=False)
    reopened_db.close()


@pytest.mark.anyio
async def test_check_populates_durable_aggregate_and_status_coverage(tmp_path: Path) -> None:
    records = replay_records("projection-rebuild")[:1]
    command, objects = command_from_records(records)
    path = tmp_path / "check-aggregate.sqlite3"
    ledger, db = file_sqlite_for(command, objects, path)
    accepted = await ledger.append_batch(command)
    # Coverage on the check payload is what the durable mirror must retain; include both
    # check types so the aggregate proves AI-powered (model-derived) coverage is not collapsed to none.
    check_coverage = _checked_coverage(
        command.entries[0].coverage, CheckType.DETERMINISTIC, CheckType.SEMANTIC_MODEL_DERIVED
    )
    await _commit_check(
        ledger,
        command,
        objects,
        accepted.result_frontier,
        request_number=91_001,
        coverage=check_coverage,
    )

    row = _projection_row(db)
    _assert_check_aggregate_consistent(row, has_check=True)
    assert row["latest_verdict"] == CheckVerdict.NO_ISSUE_DETECTED.value
    assert _check_types(row["latest_coverage_canonical"]) == [
        "deterministic",
        "semantic_model_derived",
    ]
    assert _check_types(row["status_coverage_canonical"]) == [
        "deterministic",
        "semantic_model_derived",
    ]
    assert "none" not in _check_types(row["status_coverage_canonical"])
    assert row["latest_returned_finding_ids"] == canonical_encode(())
    assert row["latest_suppressed_count"] == 0
    check_event_id = row["latest_check_event_id"]
    assert type(check_event_id) is str and check_event_id.startswith("evt_")
    db.close()

    _reopened, reopened_db = file_sqlite_for(command, objects, path)
    durable = _projection_row(reopened_db)
    _assert_check_aggregate_consistent(durable, has_check=True)
    assert durable["latest_check_event_id"] == check_event_id
    assert durable["latest_verdict"] == CheckVerdict.NO_ISSUE_DETECTED.value
    assert _check_types(durable["latest_coverage_canonical"]) == [
        "deterministic",
        "semantic_model_derived",
    ]
    assert _check_types(durable["status_coverage_canonical"]) == [
        "deterministic",
        "semantic_model_derived",
    ]
    reopened_db.close()


@pytest.mark.anyio
async def test_compact_status_names_the_latest_check_and_its_verdict(tmp_path: Path) -> None:
    """#1027: the compact item carries the check the latest tested state points at.

    A recap read after a context compaction names the check by its recorded event id, the
    frontier it examined and its closed verdict; a task that was never checked carries none.
    """

    from yoetz.ports.ledger import ProjectionQuery
    from yoetz.protocol.models import StatusCompactItemModel

    records = replay_records("projection-rebuild")[:1]
    command, objects = command_from_records(records)
    ledger, db = file_sqlite_for(command, objects, tmp_path / "latest-check.sqlite3")
    accepted = await ledger.append_batch(command)

    async def compact_item() -> StatusCompactItemModel:
        head = await ledger.load_frontier()
        page = await ledger.query_projection(
            ProjectionQuery(command.session_id, "compact", None, head, 1, None, None)
        )
        return cast(StatusCompactItemModel, page.items[0])

    assert (await compact_item()).latest_check is None
    await _commit_check(
        ledger,
        command,
        objects,
        accepted.result_frontier,
        request_number=91_031,
        coverage=_checked_coverage(command.entries[0].coverage),
        verdict=CheckVerdict.INCOMPLETE_CHECK,
    )
    row = _projection_row(db)

    latest = (await compact_item()).latest_check
    assert latest is not None
    assert latest.check_event_id == row["latest_check_event_id"]
    assert latest.verdict == CheckVerdict.INCOMPLETE_CHECK.value == row["latest_verdict"]
    assert latest.checked_frontier.sequence == str(row["latest_subject_frontier_seq"])
    assert latest.checked_frontier.head_digest == row["latest_subject_frontier_digest"]
    db.close()


@pytest.mark.anyio
async def test_ordinary_publish_after_check_does_not_resurrect_none(tmp_path: Path) -> None:
    """Ordinary append must not wipe applicable-check coverage back to envelope none.

    After a successful check the durable status coverage carries the check's types. A later
    non-material session_resumed lands on the ordinary append path; that path used to write
    ``records[-1].coverage`` (always none) and resurrect the lie.
    """

    seed = replay_records("projection-rebuild")[:1]
    command, objects = command_from_records(seed)
    path = tmp_path / "publish-after-check.sqlite3"
    ledger, db = file_sqlite_for(command, objects, path)
    accepted = await ledger.append_batch(command)
    check_coverage = _checked_coverage(command.entries[0].coverage, CheckType.DETERMINISTIC)
    await _commit_check(
        ledger,
        command,
        objects,
        accepted.result_frontier,
        request_number=92_001,
        coverage=check_coverage,
    )
    after_check = _projection_row(db)
    assert _check_types(after_check["status_coverage_canonical"]) == ["deterministic"]
    check_event_id = after_check["latest_check_event_id"]
    assert check_event_id is not None

    # session_resumed is non-material: the prior check remains applicable.
    resume_template = next(
        record
        for record in replay_records("all-event-families")
        if record.schema.name == "session_resumed"
    )
    resume_command, objects = _append_follow_on(
        seed[0],
        resume_template,
        objects,
        writer_id=command.writer_id,
        session_id=command.session_id,
        task_id=command.task_id,
        expected_frontier=after_check["frontier_seq"],
        request_number=92_010,
        event_number=92_011,
        object_number=92_012,
    )
    await ledger.append_batch(resume_command)

    row = _projection_row(db)
    assert row["latest_check_event_id"] == check_event_id
    assert _check_types(row["latest_coverage_canonical"]) == ["deterministic"]
    assert _check_types(row["status_coverage_canonical"]) == ["deterministic"]
    assert "none" not in _check_types(row["status_coverage_canonical"])
    _assert_check_aggregate_consistent(row, has_check=True)
    db.close()

    _reopened, reopened_db = file_sqlite_for(command, objects, path)
    durable = _projection_row(reopened_db)
    assert durable["latest_check_event_id"] == check_event_id
    assert _check_types(durable["status_coverage_canonical"]) == ["deterministic"]
    assert _check_types(durable["latest_coverage_canonical"]) == ["deterministic"]
    _assert_check_aggregate_consistent(durable, has_check=True)
    reopened_db.close()


def _returned_finding(command: AppendCommand, subject_frontier: Frontier, number: int) -> Finding:
    template = next(
        record.payload
        for record in replay_records("all-event-families")
        if type(record.payload) is FindingRecordedPayload
    )
    return replace(
        template,
        finding_id=finding_id(uuid_id("fnd", number)),
        subject_frontier=subject_frontier,
        coverage=command.entries[0].coverage,
    )


@pytest.mark.anyio
async def test_response_to_returned_finding_keeps_check_coverage(tmp_path: Path) -> None:
    """Issue #172: answering a finding the applicable check returned must not wipe its coverage.

    ``response_recorded`` is a material family, so the durable mirror used to fall back to the
    envelope baseline the moment an agent followed the guidance-mandated check -> respond -> receipt
    sequence. A response about the check's own output reports on that check; it does not supersede
    it, and status must agree with the receipt on that.
    """

    seed = replay_records("projection-rebuild")[:1]
    command, objects = command_from_records(seed)
    path = tmp_path / "respond-after-check.sqlite3"
    ledger, db = file_sqlite_for(command, objects, path)
    accepted = await ledger.append_batch(command)
    check_coverage = _checked_coverage(
        command.entries[0].coverage, CheckType.DETERMINISTIC, CheckType.SEMANTIC_MODEL_DERIVED
    )
    returned = _returned_finding(command, accepted.result_frontier, 95_000)
    await _commit_check(
        ledger,
        command,
        objects,
        accepted.result_frontier,
        request_number=95_001,
        coverage=check_coverage,
        verdict=CheckVerdict.ACTION_REQUIRED,
        findings=(returned,),
    )
    after_check = _projection_row(db)
    check_event_id = after_check["latest_check_event_id"]
    assert check_event_id is not None
    assert _check_types(after_check["status_coverage_canonical"]) == [
        "deterministic",
        "semantic_model_derived",
    ]

    response_template = next(
        record
        for record in replay_records("all-event-families")
        if record.schema.name == "response_recorded"
    )
    assert type(response_template.payload) is ResponseRecordedPayload
    head_row = db.execute(
        "SELECT frontier_seq, head_digest FROM p1_projection_state WHERE projection_name='work'"
    ).fetchone()
    assert head_row is not None
    response_payload = replace(
        response_template.payload,
        finding_id=returned.finding_id,
        finding_frontier=Frontier(int(head_row[0]), cast(str, head_row[1])),
    )
    response_command, objects = _append_follow_on(
        seed[0],
        response_template,
        objects,
        writer_id=command.writer_id,
        session_id=command.session_id,
        task_id=command.task_id,
        expected_frontier=after_check["frontier_seq"],
        request_number=95_010,
        event_number=95_011,
        object_number=95_012,
        payload=response_payload,
    )
    await ledger.append_batch(response_command)

    row = _projection_row(db)
    assert row["latest_check_event_id"] == check_event_id
    assert _check_types(row["status_coverage_canonical"]) == [
        "deterministic",
        "semantic_model_derived",
    ]
    assert "none" not in _check_types(row["status_coverage_canonical"])
    _assert_check_aggregate_consistent(row, has_check=True)
    db.close()

    _reopened, reopened_db = file_sqlite_for(command, objects, path)
    durable = _projection_row(reopened_db)
    assert durable["latest_check_event_id"] == check_event_id
    assert _check_types(durable["status_coverage_canonical"]) == [
        "deterministic",
        "semantic_model_derived",
    ]
    _assert_check_aggregate_consistent(durable, has_check=True)
    reopened_db.close()


@pytest.mark.anyio
async def test_response_to_unreturned_finding_resets_status_coverage(tmp_path: Path) -> None:
    """A response about a finding the applicable check never returned is untested work to it."""

    seed = replay_records("projection-rebuild")[:1]
    command, objects = command_from_records(seed)
    path = tmp_path / "respond-other-finding.sqlite3"
    ledger, db = file_sqlite_for(command, objects, path)
    accepted = await ledger.append_batch(command)
    check_coverage = _checked_coverage(command.entries[0].coverage, CheckType.DETERMINISTIC)
    returned = _returned_finding(command, accepted.result_frontier, 96_000)
    await _commit_check(
        ledger,
        command,
        objects,
        accepted.result_frontier,
        request_number=96_001,
        coverage=check_coverage,
        verdict=CheckVerdict.ACTION_REQUIRED,
        findings=(returned,),
    )
    after_check = _projection_row(db)
    assert _check_types(after_check["status_coverage_canonical"]) == ["deterministic"]

    response_template = next(
        record
        for record in replay_records("all-event-families")
        if record.schema.name == "response_recorded"
    )
    assert type(response_template.payload) is ResponseRecordedPayload
    head_row = db.execute(
        "SELECT frontier_seq, head_digest FROM p1_projection_state WHERE projection_name='work'"
    ).fetchone()
    assert head_row is not None
    response_payload = replace(
        response_template.payload,
        finding_id=finding_id(uuid_id("fnd", 96_100)),
        finding_frontier=Frontier(int(head_row[0]), cast(str, head_row[1])),
    )
    response_command, objects = _append_follow_on(
        seed[0],
        response_template,
        objects,
        writer_id=command.writer_id,
        session_id=command.session_id,
        task_id=command.task_id,
        expected_frontier=after_check["frontier_seq"],
        request_number=96_010,
        event_number=96_011,
        object_number=96_012,
        payload=response_payload,
    )
    await ledger.append_batch(response_command)

    row = _projection_row(db)
    assert _check_types(row["status_coverage_canonical"]) == ["none"]
    _assert_check_aggregate_consistent(row, has_check=True)
    db.close()

    _reopened, reopened_db = file_sqlite_for(command, objects, path)
    durable = _projection_row(reopened_db)
    assert _check_types(durable["status_coverage_canonical"]) == ["none"]
    reopened_db.close()


@pytest.mark.anyio
async def test_redaction_of_latest_check_clears_durable_aggregate(tmp_path: Path) -> None:
    """Redacting the current check must clear the durable latest-* columns.

    The reducer sets ``latest_tested_state`` to None when ``redaction_recorded`` targets
    that check. The ordinary append path used to refresh only status coverage/gaps and
    leave the seven latest-check columns advertising the redacted verdict after restart.
    """

    seed = replay_records("projection-rebuild")[:1]
    command, objects = command_from_records(seed)
    path = tmp_path / "redact-check-aggregate.sqlite3"
    ledger, db = file_sqlite_for(command, objects, path)
    accepted = await ledger.append_batch(command)
    check_coverage = _checked_coverage(command.entries[0].coverage, CheckType.DETERMINISTIC)
    await _commit_check(
        ledger,
        command,
        objects,
        accepted.result_frontier,
        request_number=94_001,
        coverage=check_coverage,
    )
    after_check = _projection_row(db)
    _assert_check_aggregate_consistent(after_check, has_check=True)
    check_event_id = after_check["latest_check_event_id"]
    assert type(check_event_id) is str

    redaction_template = next(
        record
        for record in replay_records("all-event-families")
        if record.schema.name == "redaction_recorded"
    )
    assert type(redaction_template.payload) is RedactionRecordedPayload
    redaction_payload = replace(
        redaction_template.payload,
        target_event_ids=(event_id(check_event_id),),
        target_object_ids=(),
    )
    redaction_command, objects = _append_follow_on(
        seed[0],
        redaction_template,
        objects,
        writer_id=command.writer_id,
        session_id=command.session_id,
        task_id=command.task_id,
        expected_frontier=after_check["frontier_seq"],
        request_number=94_010,
        event_number=94_011,
        object_number=94_012,
        payload=redaction_payload,
    )
    await ledger.append_batch(redaction_command)

    row = _projection_row(db)
    _assert_check_aggregate_consistent(row, has_check=False)
    # No applicable check remains; compact status falls back to the redaction envelope.
    assert _check_types(row["status_coverage_canonical"]) == ["none"]
    gaps = strict_json_parse(row["status_gap_codes_canonical"])
    assert type(gaps) is list
    assert any(type(marker) is str and marker.startswith("redacted_event:") for marker in gaps), (
        gaps
    )
    db.close()

    _reopened, reopened_db = file_sqlite_for(command, objects, path)
    durable = _projection_row(reopened_db)
    _assert_check_aggregate_consistent(durable, has_check=False)
    assert _check_types(durable["status_coverage_canonical"]) == ["none"]
    reopened_db.close()


@pytest.mark.anyio
async def test_two_checks_update_aggregate_and_keep_constraints(tmp_path: Path) -> None:
    records = replay_records("projection-rebuild")[:1]
    command, objects = command_from_records(records)
    path = tmp_path / "two-checks.sqlite3"
    ledger, db = file_sqlite_for(command, objects, path)
    accepted = await ledger.append_batch(command)

    first_coverage = _checked_coverage(command.entries[0].coverage, CheckType.DETERMINISTIC)
    await _commit_check(
        ledger,
        command,
        objects,
        accepted.result_frontier,
        request_number=93_001,
        coverage=first_coverage,
        verdict=CheckVerdict.NO_ISSUE_DETECTED,
    )
    first = _projection_row(db)
    _assert_check_aggregate_consistent(first, has_check=True)
    first_check_id = first["latest_check_event_id"]
    head_row = db.execute(
        "SELECT frontier_seq, head_digest FROM p1_projection_state WHERE projection_name='work'"
    ).fetchone()
    assert head_row is not None
    second_subject = Frontier(int(head_row[0]), cast(str, head_row[1]))

    second_coverage = _checked_coverage(
        command.entries[0].coverage, CheckType.DETERMINISTIC, CheckType.SEMANTIC_MODEL_DERIVED
    )
    await _commit_check(
        ledger,
        command,
        objects,
        second_subject,
        request_number=93_002,
        coverage=second_coverage,
        verdict=CheckVerdict.INSUFFICIENT_COVERAGE,
        suppressed_count=2,
    )
    second = _projection_row(db)
    _assert_check_aggregate_consistent(second, has_check=True)
    assert second["latest_check_event_id"] != first_check_id
    assert second["latest_verdict"] == CheckVerdict.INSUFFICIENT_COVERAGE.value
    assert second["latest_suppressed_count"] == 2
    assert _check_types(second["latest_coverage_canonical"]) == [
        "deterministic",
        "semantic_model_derived",
    ]
    assert _check_types(second["status_coverage_canonical"]) == [
        "deterministic",
        "semantic_model_derived",
    ]
    # Subject of the second check is the post-first-check head, not the original seed.
    assert second["latest_subject_frontier_seq"] == first["frontier_seq"]
    db.close()

    _reopened, reopened_db = file_sqlite_for(command, objects, path)
    durable = _projection_row(reopened_db)
    _assert_check_aggregate_consistent(durable, has_check=True)
    assert durable["latest_check_event_id"] == second["latest_check_event_id"]
    assert durable["latest_verdict"] == CheckVerdict.INSUFFICIENT_COVERAGE.value
    assert _check_types(durable["status_coverage_canonical"]) == [
        "deterministic",
        "semantic_model_derived",
    ]
    reopened_db.close()


def _append_follow_on(
    seed: LedgerRecord,
    template: LedgerRecord,
    objects: MemoryObjects,
    *,
    writer_id: str,
    session_id: str,
    task_id: str,
    expected_frontier: int,
    request_number: int,
    event_number: int,
    object_number: int,
    payload: EventPayload | None = None,
) -> tuple[AppendCommand, MemoryObjects]:
    assert template.payload is not None or payload is not None
    typed_payload = cast(EventPayload, payload if payload is not None else template.payload)
    # Redaction envelopes mirror target_object_ids in artifact_refs; rebuild when the
    # payload is overridden so EventDraft ref-mirror validation stays honest.
    if type(typed_payload) is RedactionRecordedPayload:
        artifact_refs = typed_payload.target_object_ids
    else:
        artifact_refs = template.artifact_refs
    event = event_id(uuid_id("evt", event_number))
    payload_object = object_id(uuid_id("obj", object_number))
    draft = EventDraft(
        event,
        template.schema,
        template.occurred_at,
        (),
        typed_payload,
        artifact_refs,
        template.evidence_refs,
    )
    metadata = ObjectMetadata(
        ObjectKind.EVENT_PAYLOAD,
        template.payload_ref.media_type,
        task_id,
        parse_rfc3339_millis(template.ledger.accepted_at.wire),
    )
    payload_bytes = canonical_encode(encode_payload(typed_payload))
    ref = ObjectRef(
        payload_object,
        len(payload_bytes),
        template.payload_ref.commitment,
        "sha256:" + "c" * 64,
        "yoetz-object/1",
        "slot-1",
        metadata,
    )
    objects._data[ref.object_id] = payload_bytes  # pyright: ignore[reportPrivateUsage]
    operation_id = uuid_id("req", request_number)
    entry = AppendEntry(
        draft,
        seed.author if seed.author.actor_type.value != "yoetz_engine" else template.author,
        ref,
        ref.commitment,
        metadata.media_type,
        ref.plaintext_size,
        template.publication_channel,
        template.coverage,
        "projected",
    )
    command = AppendCommand(
        task_id,
        session_id,
        writer_id,
        operation_id,
        OperationKind.PUBLISH_WORK,
        canonical_digest({"event_ids": (event,), "operation_id": operation_id}),
        expected_frontier,
        (entry,),
    )
    return command, objects
