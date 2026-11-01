"""One answer to "what followed the last check" on every surface (tb4n3 RC-6, issue #1029).

tb4n3 measured the defect on real Codex runs: the records that follow a deterministic arm's final
check are the ``check`` call's own hook observation and host stream bookkeeping, so
``check_current_as_of_earlier_frontier`` bounded 17 of 17 final receipts and was the sole bound in
three D attempts. Conversely an observed edit after the check produced the same standing code, so
it was indistinguishable from a status poll (C7).

These tests drive the real ``Application`` facade over both ledger backends and assert the same
fact on each surface that reads the check's applicability: the receipt-capacity gap fold, compact
status coverage and freshness, closure readiness, the receipt JSON document and its markdown and
text renderings.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal, cast

import pytest

from builders.start_application import protocol_id, start_request
from finishup.application.observation_materialize import observation_author
from finishup.application.service import Application
from finishup.application.start import StartInternalResult
from finishup.cli.render import render_closure_readiness_lines
from finishup.domain.events import (
    EVIDENCE_SCHEMA_VERSION,
    ActionKind,
    ActionRecordedPayload,
    EventDraft,
    EventPayload,
    EventSchema,
    EvidenceKind,
    EvidenceRecordedPayload,
    ResultOutcome,
    ResultRecordedPayload,
    encode_payload,
    media_type_for,
)
from finishup.domain.values import (
    action_id,
    event_id,
    evidence_id,
    result_id,
    timestamp_from_datetime,
)
from finishup.kernel.later_material import (
    COMPLETION_SIGNAL_PREFIX,
    OPAQUE_OBSERVATION_PREFIX,
)
from finishup.kernel.observed_failures import observed_action_description
from finishup.kernel.receipt_capacity import receipt_gap_codes
from finishup.kernel.reducers import replay
from finishup.mcp.summaries import _MAX_SUMMARY_BYTES, _check_cause_variants, summary_for_status
from finishup.ports.ledger import AppendCommand, AppendEntry, CheckCommitResult, OperationKind
from finishup.ports.objects import ObjectKind, ObjectMetadata, ObjectSource
from finishup.protocol.canonical import canonical_encode
from finishup.protocol.coverage import (
    EvidenceImmutability,
    LedgerFreshness,
    PublicationChannel,
    coverage_for_channel,
)
from finishup.protocol.models import CheckRequest, ReceiptRequest, StatusRequest
from integration.application import test_respond_status_receipt as h

pytestmark = pytest.mark.anyio

_CCAOEF = "check_current_as_of_earlier_frontier"
_NOT_APPLICABLE = "check_not_applicable"

type _Item = tuple[str, EventPayload]


def _action(seed: int, kind: ActionKind, tool: str, runner: str | None, **runtime: Any) -> _Item:
    return (
        "action_recorded",
        ActionRecordedPayload(
            action_id(protocol_id("act_", seed)),
            kind,
            observed_action_description(
                f"Observed {kind.value} via Codex hook", tool, runner, **runtime
            ),
            command="omitted:structural" if kind is ActionKind.COMMAND else None,
        ),
    )


def _result(seed: int, action_seed: int) -> _Item:
    return (
        "result_recorded",
        ResultRecordedPayload(
            result_id(protocol_id("res_", seed)),
            action_id(protocol_id("act_", action_seed)),
            ResultOutcome.SUCCESS,
            exit_status=0,
            summary="Observed result status=success",
        ),
    )


def _evidence(seed: int, description: str) -> _Item:
    return (
        "evidence_recorded",
        EvidenceRecordedPayload(
            evidence_id(protocol_id("evd_", seed)),
            EvidenceKind.OTHER,
            EvidenceImmutability.METADATA_ONLY,
            timestamp_from_datetime(datetime(2026, 7, 19, 12, 5, tzinfo=UTC)),
            description=description,
        ),
    )


def _own_calls_and_bookkeeping(seed: int) -> tuple[_Item, ...]:
    """What the real tb4n3 suffix is: the ``check`` call's own post, then host stream rows."""

    return (
        _action(seed, ActionKind.OTHER, "mcp__finishup__check", "lint"),
        _result(seed + 1, seed),
        _action(seed + 2, ActionKind.OTHER, "mcp__finishup__status", "other"),
        _result(seed + 3, seed + 2),
        _action(seed + 4, ActionKind.OTHER, "mcp__finishup__receipt", "other"),
        _result(seed + 5, seed + 4),
        _evidence(seed + 6, f"{OPAQUE_OBSERVATION_PREFIX}event_msg"),
        _evidence(seed + 7, f"{OPAQUE_OBSERVATION_PREFIX}response_item"),
        _evidence(seed + 8, f"{OPAQUE_OBSERVATION_PREFIX}token_usage_record"),
        _evidence(seed + 9, f"{COMPLETION_SIGNAL_PREFIX}AgentMessage"),
    )


async def _append_observed(
    app: Application,
    runtime: Any,
    started: StartInternalResult,
    items: tuple[_Item, ...],
    *,
    seed: int,
    expected_frontier: int,
) -> Any:
    ledger, objects = next(iter(runtime.resources.values()))
    now = app.clock.now_utc()
    entries: list[AppendEntry] = []
    for offset, (schema_name, payload) in enumerate(items):
        encoded = canonical_encode(encode_payload(payload))
        metadata = ObjectMetadata(
            ObjectKind.EVENT_PAYLOAD, media_type_for(schema_name), started.task_id, now
        )
        staged = await objects.stage(
            ObjectSource(data=encoded, declared_size=len(encoded)), metadata
        )
        payload_ref = await objects.finalize(staged)
        schema_version = EVIDENCE_SCHEMA_VERSION if schema_name == "evidence_recorded" else "1.0.0"
        entries.append(
            AppendEntry(
                EventDraft(
                    event_id(protocol_id("evt_", seed + 100 + offset)),
                    EventSchema(schema_name, schema_version),
                    timestamp_from_datetime(now),
                    (),
                    payload,
                    (),
                    (),
                ),
                observation_author(),
                payload_ref,
                payload_ref.commitment,
                metadata.media_type,
                payload_ref.plaintext_size,
                PublicationChannel.HOOK_OBSERVED,
                coverage_for_channel(PublicationChannel.HOOK_OBSERVED),
                "projected",
            )
        )
    return await ledger.append_batch(
        AppendCommand(
            started.task_id,
            started.session_id,
            started.writer_id,
            protocol_id("req_", seed + 90),
            OperationKind.PUBLISH_WORK,
            h._DIGEST,
            expected_frontier,
            tuple(entries),
            None,
        )
    )


async def _checked(
    app: Application, runtime: Any, backend: str
) -> tuple[StartInternalResult, CheckCommitResult]:
    started = await app.start(start_request(5100, title="tb4n3 own calls"))
    checked = await app.check(
        CheckRequest.model_validate(
            {
                **h._request_base(protocol_id("req_", 5110)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": h._frontier(started.frontier),
                "mode": "deterministic_only",
                "max_findings": "3",
            }
        )
    )
    assert type(checked) is CheckCommitResult
    assert checked.findings == ()
    return started, checked


async def _surfaces(
    app: Application,
    runtime: Any,
    started: StartInternalResult,
    appended_frontier: Any,
    seed: int,
) -> dict[str, Any]:
    """Every surface that reads the check's applicability, at the same frontier."""

    ledger, _objects = next(iter(runtime.resources.values()))
    records = tuple([record async for record in ledger.load_events(started.session_id)])
    status = await app.status(
        StatusRequest.model_validate(
            {
                **h._request_base(protocol_id("req_", seed)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "view": "compact",
                "limit": "10",
            }
        )
    )
    receipts: dict[str, Any] = {}
    for offset, fmt in enumerate(("json", "markdown", "text")):
        receipts[fmt] = await app.receipt(
            ReceiptRequest.model_validate(
                {
                    **h._receipt_wire(
                        seed + 10 + offset,
                        task_id=started.task_id,
                        session=started.session_id,
                        writer=started.writer_id,
                        frontier=appended_frontier,
                    ),
                    "format": fmt,
                }
            )
        )
    return {
        "capacity": receipt_gap_codes(replay(records), records),
        "status": status,
        "compact": cast(Any, status.page).items[0],
        "receipts": receipts,
    }


def _readiness_text(status: Any) -> tuple[str, str]:
    """The lineage sentence as the CLI/terminal interface and the MCP text reconstruct it."""

    cli = "\n".join(render_closure_readiness_lines(status.closure_readiness))
    variants = _check_cause_variants(status.as_json())
    return cli, variants[0] if variants else ""


def _limitations(receipt: Any) -> str:
    if receipt.document is not None:
        return h._limitations_body(receipt.document)
    return cast(str, receipt.human_text)


@pytest.mark.parametrize("backend", ("memory", "sqlite"))
async def test_own_calls_and_host_bookkeeping_after_the_check_leave_it_current(
    backend: Literal["memory", "sqlite"],
) -> None:
    """(a) check -> only FinishUP's own calls and stream bookkeeping -> receipt: no earlier-frontier
    gap on any surface, and the deterministic arm's receipt reads clean."""

    app, runtime, _ = h._build_app(seed_offset=60, ledger_backend=backend)
    started, checked = await _checked(app, runtime, backend)

    baseline = await app.receipt(
        ReceiptRequest.model_validate(
            h._receipt_wire(
                5120,
                task_id=started.task_id,
                session=started.session_id,
                writer=started.writer_id,
                frontier=checked.result_frontier,
            )
        )
    )
    assert baseline.conclusion == "no_unresolved_deterministic_findings"

    appended = await _append_observed(
        app,
        runtime,
        started,
        _own_calls_and_bookkeeping(5200),
        seed=5200,
        expected_frontier=baseline.result_frontier.sequence,
    )
    surfaces = await _surfaces(app, runtime, started, appended.result_frontier, 5300)

    assert _CCAOEF not in surfaces["capacity"]
    assert _NOT_APPLICABLE not in surfaces["capacity"]
    compact = surfaces["compact"]
    assert _CCAOEF not in compact.coverage.known_gaps
    assert _CCAOEF not in compact.gaps
    assert compact.freshness != LedgerFreshness.STALE_AFTER_MATERIAL_CHANGE.value
    status = surfaces["status"]
    assert _CCAOEF not in status.coverage.known_gaps
    assert _CCAOEF not in status.closure_readiness.standing_limitations
    assert _NOT_APPLICABLE not in status.closure_readiness.agent_actionable
    assert _CCAOEF not in status.closure_readiness.agent_actionable
    assert status.closure_readiness.check_cause is None
    cli, mcp = _readiness_text(status)
    assert "Why check_" not in cli and mcp == ""
    for fmt, receipt in surfaces["receipts"].items():
        assert _CCAOEF not in receipt.coverage.known_gaps, fmt
        assert _NOT_APPLICABLE not in receipt.coverage.known_gaps, fmt
        assert receipt.conclusion == "no_unresolved_deterministic_findings", fmt
        assert "current as of" not in _limitations(receipt), fmt


@pytest.mark.parametrize("backend", ("memory", "sqlite"))
async def test_an_unclassified_command_after_the_check_still_keeps_the_disclosure(
    backend: Literal["memory", "sqlite"],
) -> None:
    """Control: what FinishUP cannot prove harmless (a script run) keeps the earlier-frontier note,
    exactly as before, and bounds the conclusion on every surface alike."""

    app, runtime, _ = h._build_app(seed_offset=61, ledger_backend=backend)
    started, checked = await _checked(app, runtime, backend)
    appended = await _append_observed(
        app,
        runtime,
        started,
        (
            *_own_calls_and_bookkeeping(5400),
            _action(5420, ActionKind.COMMAND, "exec_command", "other"),
            _result(5421, 5420),
        ),
        seed=5400,
        expected_frontier=checked.result_frontier.sequence,
    )
    surfaces = await _surfaces(app, runtime, started, appended.result_frontier, 5500)

    assert _CCAOEF in surfaces["capacity"]
    assert _NOT_APPLICABLE not in surfaces["capacity"]
    assert _CCAOEF in surfaces["compact"].coverage.known_gaps
    # Readiness keeps the code a standing limitation (any recheck instruction derived from it can
    # regenerate after the check it asks for: the FinishUP CLI run through a shell, Cursor's
    # tool-identity-free results; ADR-040 section 7), and names the first record (owner lineage).
    readiness = surfaces["status"].closure_readiness
    assert _CCAOEF in readiness.standing_limitations
    assert _CCAOEF not in readiness.agent_actionable
    cause = readiness.check_cause
    assert cause is not None
    assert (cause.effect, cause.material_class, cause.rule, cause.tool) == (
        "bounds_conclusion",
        "other",
        "unclassified_observed_action",
        "exec_command",
    )
    assert cause.check_subject_frontier == str(checked.subject_frontier.sequence)
    cli, mcp = _readiness_text(surfaces["status"])
    assert "Why check_current_as_of_earlier_frontier" in cli
    assert mcp and mcp.strip() in cli
    for fmt, receipt in surfaces["receipts"].items():
        assert _CCAOEF in receipt.coverage.known_gaps, fmt
        assert receipt.conclusion == "insufficient_coverage", fmt
        body = _limitations(receipt)
        assert "Its verdict is current as of subject frontier" in body, fmt
        assert "rule unclassified_observed_action" in body, fmt
        assert "Not counted, because FinishUP classified them" in body, fmt


@pytest.mark.parametrize("backend", ("memory", "sqlite"))
async def test_an_observed_deliverable_edit_after_the_check_supersedes_it(
    backend: Literal["memory", "sqlite"],
) -> None:
    """(b) check -> deliverable edit -> every surface says the check no longer covers the state
    and that the closing check is needed again (C7, test_c4_observed_edit_after_check...)."""

    app, runtime, _ = h._build_app(seed_offset=62, ledger_backend=backend)
    started, checked = await _checked(app, runtime, backend)
    appended = await _append_observed(
        app,
        runtime,
        started,
        (
            *_own_calls_and_bookkeeping(5600),
            _action(5620, ActionKind.EDIT, "apply_patch", "compound"),
            _result(5621, 5620),
        ),
        seed=5600,
        expected_frontier=checked.result_frontier.sequence,
    )
    surfaces = await _surfaces(app, runtime, started, appended.result_frontier, 5700)

    assert _NOT_APPLICABLE in surfaces["capacity"]
    assert _CCAOEF not in surfaces["capacity"]
    compact = surfaces["compact"]
    assert compact.freshness == LedgerFreshness.STALE_AFTER_MATERIAL_CHANGE.value
    status = surfaces["status"]
    assert status.closure_readiness.state == "action_required"
    assert _NOT_APPLICABLE in status.closure_readiness.agent_actionable
    cause = status.closure_readiness.check_cause
    assert cause is not None
    assert (cause.effect, cause.material_class, cause.rule, cause.tool) == (
        "superseded",
        "edit_or_write",
        "observed_counting_edit",
        "apply_patch",
    )
    assert cause.check_subject_frontier == str(checked.subject_frontier.sequence)
    cli, mcp = _readiness_text(status)
    sentence = (
        f"Why check_not_applicable: an observed edit via apply_patch (ledger record "
        f"{cause.ledger_sequence}, {cause.event_id}) was recorded after the check at subject "
        f"frontier {checked.subject_frontier.sequence} (rule observed_counting_edit)."
    )
    assert sentence in cli
    assert sentence in mcp
    for fmt, receipt in surfaces["receipts"].items():
        assert _NOT_APPLICABLE in receipt.coverage.known_gaps, fmt
        assert receipt.conclusion == "insufficient_coverage", fmt
        body = _limitations(receipt)
        assert "no longer covers frontier" in body, fmt
        assert "Re-run check" in body, fmt
        # The same record, named by the same rule, on the receipt as on status.
        assert f"ledger record {cause.ledger_sequence}, {cause.event_id}" in body, fmt
        assert "rule observed_counting_edit" in body, fmt
    receipt_document = surfaces["receipts"]["json"].document
    gap = next(g for g in receipt_document["gaps"] if g["code"] == _NOT_APPLICABLE)
    assert tuple(gap["subject_refs"]) == (cause.event_id,)

    # The remedy the surfaces name works: a new check restores applicability, and the check's own
    # observation that lands after it does not take it away again.
    rechecked = await app.check(
        CheckRequest.model_validate(
            {
                **h._request_base(protocol_id("req_", 5800)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                # The three receipts above each advanced the head with an immaterial record.
                "expected_frontier": h._frontier(surfaces["receipts"]["text"].result_frontier),
                "mode": "deterministic_only",
                "max_findings": "3",
            }
        )
    )
    assert type(rechecked) is CheckCommitResult
    after = await _append_observed(
        app,
        runtime,
        started,
        _own_calls_and_bookkeeping(5900),
        seed=5900,
        expected_frontier=rechecked.result_frontier.sequence,
    )
    final = await _surfaces(app, runtime, started, after.result_frontier, 6000)
    assert _NOT_APPLICABLE not in final["capacity"]
    assert _CCAOEF not in final["capacity"]
    for fmt, receipt in final["receipts"].items():
        # What remains is the check-time capture a repository-less test harness cannot read; the
        # earlier-frontier and superseded-check codes are both gone.
        assert _CCAOEF not in receipt.coverage.known_gaps, fmt
        assert _NOT_APPLICABLE not in receipt.coverage.known_gaps, fmt
        assert "no longer covers frontier" not in _limitations(receipt), fmt
    assert final["compact"].freshness != LedgerFreshness.STALE_AFTER_MATERIAL_CHANGE.value


@pytest.mark.parametrize("backend", ("memory", "sqlite"))
async def test_a_saved_finishup_receipt_or_scratch_write_never_supersedes_the_check(
    backend: Literal["memory", "sqlite"],
) -> None:
    """A receipt the agent saves is the output *about* the check: counting it would invalidate the
    check that produced it, and the next receipt would do it again."""

    app, runtime, _ = h._build_app(seed_offset=63, ledger_backend=backend)
    started, checked = await _checked(app, runtime, backend)
    appended = await _append_observed(
        app,
        runtime,
        started,
        (
            _action(6100, ActionKind.EDIT, "apply_patch", "compound", write_scope="yoetz_owned"),
            _result(6101, 6100),
            _action(6102, ActionKind.EDIT, "apply_patch", "compound", write_scope="scratch"),
            _result(6103, 6102),
        ),
        seed=6100,
        expected_frontier=checked.result_frontier.sequence,
    )
    surfaces = await _surfaces(app, runtime, started, appended.result_frontier, 6200)
    assert _NOT_APPLICABLE not in surfaces["capacity"]
    assert _CCAOEF not in surfaces["capacity"]
    assert surfaces["receipts"]["json"].conclusion == "no_unresolved_deterministic_findings"


@pytest.mark.parametrize("backend", ("memory", "sqlite"))
async def test_a_mixed_suffix_names_the_observation_that_bounds_not_the_response(
    backend: Literal["memory", "sqlite"],
) -> None:
    """Codex review 1: an answer to the check's finding followed by a script run. The cause on
    status and the cited records on the receipt are the observation; the advisory answer never
    stands in for it."""

    from finishup.protocol.models import RespondRequest

    app, runtime, _ = h._build_app(seed_offset=64, ledger_backend=backend)
    started, checked, _obligation = await h._bootstrap_finding(app, seed=6400)
    finding = checked.findings[0]
    responded = await app.respond(
        RespondRequest.model_validate(
            {
                **h._request_base(protocol_id("req_", 6410)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": h._frontier(checked.result_frontier),
                "finding_id": finding.finding_id,
                "finding_frontier": h._frontier(checked.result_frontier),
                "disposition": "acknowledged",
            }
        )
    )
    appended = await _append_observed(
        app,
        runtime,
        started,
        (_action(6420, ActionKind.COMMAND, "exec_command", "other"), _result(6421, 6420)),
        seed=6420,
        expected_frontier=responded.result_frontier.sequence,
    )
    surfaces = await _surfaces(app, runtime, started, appended.result_frontier, 6700)
    readiness = surfaces["status"].closure_readiness
    assert _CCAOEF in readiness.standing_limitations
    cause = readiness.check_cause
    assert cause is not None and cause.effect == "bounds_conclusion"
    assert (cause.family, cause.material_class, cause.tool) == (
        "action_recorded",
        "other",
        "exec_command",
    )
    gap = next(g for g in surfaces["receipts"]["json"].document["gaps"] if g["code"] == _CCAOEF)
    # The observation is cited first; the answer follows it.
    assert cause.event_id in gap["subject_refs"]
    assert len(gap["subject_refs"]) == 3  # the script's action, its result, the answer


async def test_the_lineage_sentence_survives_the_status_text_budget() -> None:
    """Codex review 2: the MCP text has a full and a short form of the cause, never a half one."""

    app, runtime, _ = h._build_app(seed_offset=65)
    started, checked = await _checked(app, runtime, "memory")
    appended = await _append_observed(
        app,
        runtime,
        started,
        (_action(6800, ActionKind.EDIT, "apply_patch", "compound"), _result(6801, 6800)),
        seed=6800,
        expected_frontier=checked.result_frontier.sequence,
    )
    surfaces = await _surfaces(app, runtime, started, appended.result_frontier, 6900)
    wire = surfaces["status"].as_json()
    full, short = _check_cause_variants(wire)
    assert "ledger record" in full and "rule observed_counting_edit" in full
    assert len(short) < len(full)
    assert "observed edit via apply_patch" in short and "frontier" in short
    assert _check_cause_variants({"closure_readiness": {"check_cause": {"effect": "x"}}}) == ()


@pytest.mark.parametrize("view", ("compact", "advice", "obligations"))
async def test_the_real_mcp_status_text_carries_the_cause_in_its_byte_budget(view: str) -> None:
    """Codex round 3: the cause is reserved ahead of the closure boilerplate on every view that
    names the closure state, so the text a host shows never lists ``check_not_applicable`` without
    the record behind it."""

    app, runtime, _ = h._build_app(seed_offset=66)
    started, checked = await _checked(app, runtime, "memory")
    appended = await _append_observed(
        app,
        runtime,
        started,
        (_action(7000, ActionKind.EDIT, "apply_patch", "compound"), _result(7001, 7000)),
        seed=7000,
        expected_frontier=checked.result_frontier.sequence,
    )
    status = await app.status(
        StatusRequest.model_validate(
            {
                **h._request_base(protocol_id("req_", 7200)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "view": view,
                "limit": "10",
            }
        )
    )
    del appended
    summary = summary_for_status(status.as_json())
    assert len(summary.encode("ascii")) <= _MAX_SUMMARY_BYTES
    assert "check_not_applicable" in summary
    assert "Why check_not_applicable: " in summary, summary
    assert "observed edit via apply_patch" in summary
