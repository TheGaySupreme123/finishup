"""An agent can read back and find its own evidence without widening any sink (issue #914).

Every test runs the daemon's exact post-commit projection for an MCP bridge client through the
production-composed ``LocalPrivacyEnforcer`` (``ready_composition.build_local_privacy_enforcer``)
and the shipped default policy, whose ``agent_context`` ceiling does not grant
``evidence_excerpt``. The agent's requests use the cooperative MCP wire shape; host-observed rows
come from the canonical OBS-001 captured-evidence envelope materialized for the task and appended
under the observation coordinator's own writer, as the observation drain does.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from typing import cast

import pytest

from builders.ledger_adapters import MemoryObjects
from builders.projection_workflow import (
    ProjectionCase,
    build_projection_application,
    frontier_json,
    project_case,
    request_base,
)
from builders.start_application import MemoryStartRuntime, protocol_id, start_request
from finishup.adapters.memory.ledger import MemoryLedgerAdapter
from finishup.adapters.memory.privacy import MemoryPrivacyAudit
from finishup.application.observation_materialize import (
    materialize_observation_envelope,
    observation_author,
    observation_writer_id,
)
from finishup.application.publish_work import PublishWorkInternalResult
from finishup.application.service import Application
from finishup.application.start import StartInternalResult
from finishup.application.status import StatusInternalResult
from finishup.domain.events import (
    EventDraft,
    EventSchema,
    EvidenceKind,
    EvidenceRecordedPayload,
    RedactionMethod,
    RedactionReasonCategory,
    RedactionRecordedPayload,
    encode_payload,
    media_type_for,
)
from finishup.domain.observation import (
    ObservationContentKind,
    ObservationContentManifest,
    ObservationCursor,
    ObservationEnvelope,
    ObservationSource,
)
from finishup.domain.privacy import (
    AgentProjectionAuditSubject,
    DataCategory,
    DisclosureProvenance,
)
from finishup.domain.values import (
    Actor,
    ActorType,
    Frontier,
    JsonObject,
    Timestamp,
    actor_id,
    event_id,
    evidence_id,
    object_id,
    timestamp_from_datetime,
)
from finishup.ports.control import ControlMethod
from finishup.ports.ledger import AppendCommand, AppendEntry, OperationKind
from finishup.ports.objects import ObjectKind, ObjectMetadata, ObjectSource
from finishup.ports.privacy import PrivacyReceiptAudience
from finishup.protocol.canonical import JsonValue, canonical_encode
from finishup.protocol.coverage import (
    AuthorshipAssurance,
    Coverage,
    EvidenceImmutability,
    PublicationChannel,
    coverage_for_channel,
)
from finishup.protocol.errors import PublicOperationError
from finishup.protocol.models import FrontierModel, PublishWorkRequest, StatusRequest
from fixture_loader import load_fixture_json

pytestmark = pytest.mark.anyio

_DIGEST = "sha256:" + "4" * 64
_MUTABLE_REFERENCE = EvidenceImmutability.MUTABLE_REFERENCE
_OMITTED = {
    "category": "evidence_excerpt",
    "omitted": True,
    "reason": "local_disclosure_not_authorized",
}
# The two items the dateutil semantic attempt published at codex.txt L167 (descriptions trimmed).
_DIFF_DESCRIPTION = (
    "Commit de58a86 source diff (22,099 bytes). Bounded changed-code excerpt: _date_property "
    "emits Z for UTC and TZID for named local time."
)
_TEST_DESCRIPTION = (
    "PYTHONPATH=src /usr/local/bin/python -m pytest tests -q: 2036 passed, 47 skipped, "
    "16 xfailed in 1.94s."
)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _evidence_draft(
    seed: int,
    *,
    kind: str,
    subject: str,
    description: str,
    reference: str,
) -> dict[str, JsonValue]:
    return {
        "event_id": protocol_id("evt_", seed),
        "schema": {"name": "evidence_recorded", "version": "1.1.0"},
        "occurred_at": "2026-07-28T12:00:04.000Z",
        "causal_parents": [],
        "payload": {
            "evidence_id": protocol_id("evd_", seed),
            "evidence_kind": kind,
            "strength": "content_digest",
            "observed_at": "2026-07-28T12:00:04.000Z",
            "description": description,
            "reference": reference,
            "content_digest": "sha256:" + f"{seed:x}".rjust(64, "a"),
            "digest_binding": {
                "subject": subject,
                "content_availability": "digest_only",
                "byte_count": 22099,
                "provenance": "caller_asserted",
            },
        },
        "artifact_refs": [],
        "evidence_refs": [],
    }


async def _start(app: Application, seed: int) -> StartInternalResult:
    started = await app.start(start_request(seed, title="Evidence read-back", refs=True))
    assert type(started) is StartInternalResult
    return started


async def _publish(
    app: Application,
    started: StartInternalResult,
    seed: int,
    frontier: Frontier | FrontierModel,
    drafts: Sequence[dict[str, JsonValue]],
) -> PublishWorkInternalResult:
    body: dict[str, JsonValue] = {
        **request_base(protocol_id("req_", seed)),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": frontier_json(frontier),
        "event_drafts": list(drafts),
    }
    published = await app.publish_work(PublishWorkRequest.model_validate(body))
    assert type(published) is PublishWorkInternalResult
    return published


async def _publish_agent_evidence(
    app: Application, started: StartInternalResult, seed: int
) -> tuple[PublishWorkInternalResult, str, str]:
    published = await _publish(
        app,
        started,
        seed,
        started.frontier,
        (
            _evidence_draft(
                seed + 1,
                kind="artifact",
                subject="source_diff",
                description=_DIFF_DESCRIPTION,
                reference="git show de58a86",
            ),
            _evidence_draft(
                seed + 2,
                kind="test_result",
                subject="test_stdout",
                description=_TEST_DESCRIPTION,
                reference="pytest tests -q",
            ),
        ),
    )
    return published, protocol_id("evd_", seed + 1), protocol_id("evd_", seed + 2)


def _ledger(app: Application, task_id: str) -> tuple[MemoryLedgerAdapter, MemoryObjects]:
    return cast(MemoryStartRuntime, app.runtime).resources[task_id]


async def _append(
    app: Application,
    started: StartInternalResult,
    *,
    seed: int,
    expected_frontier: int,
    writer: str,
    author: Actor,
    channel: PublicationChannel,
    drafts: Sequence[tuple[EventDraft, bytes]],
    coverage: Coverage | None = None,
) -> Frontier:
    """Append ledger entries the way a service-side writer does, bypassing ``publish_work``."""

    ledger, objects = _ledger(app, started.task_id)
    now = app.clock.now_utc()
    entries: list[AppendEntry] = []
    for draft, payload_bytes in drafts:
        metadata = ObjectMetadata(
            ObjectKind.EVENT_PAYLOAD, media_type_for(draft.schema.name), started.task_id, now
        )
        staged = await objects.stage(
            ObjectSource(data=payload_bytes, declared_size=len(payload_bytes)), metadata
        )
        payload_ref = await objects.finalize(staged)
        entries.append(
            AppendEntry(
                draft,
                author,
                payload_ref,
                payload_ref.commitment,
                metadata.media_type,
                payload_ref.plaintext_size,
                channel,
                coverage_for_channel(channel) if coverage is None else coverage,
                "projected",
            )
        )
    result = await ledger.append_batch(
        AppendCommand(
            started.task_id,
            started.session_id,
            writer,
            protocol_id("req_", seed),
            OperationKind.PUBLISH_WORK,
            _DIGEST,
            expected_frontier,
            tuple(entries),
            None,
        )
    )
    frontier = result.result_frontier
    assert type(frontier) is Frontier
    return frontier


def _plain_evidence(
    seed: int, description: str, *, strength: EvidenceImmutability
) -> tuple[EventDraft, bytes]:
    snapshot = strength is EvidenceImmutability.IMMUTABLE_SNAPSHOT
    captured = object_id(protocol_id("obj_", seed)) if snapshot else None
    payload = EvidenceRecordedPayload(
        evidence_id(protocol_id("evd_", seed)),
        EvidenceKind.ARTIFACT,
        strength,
        timestamp_from_datetime(datetime(2026, 7, 28, 12, 1, tzinfo=UTC)),
        description=description,
        reference=f"reference for {description}",
        captured_object_id=captured,
        content_digest=("sha256:" + "9" * 64) if snapshot else None,
    )
    draft = EventDraft(
        event_id(protocol_id("evt_", seed)),
        EventSchema("evidence_recorded", "1.0.0"),
        payload.observed_at,
        (),
        payload,
        () if captured is None else (captured,),
        (),
    )
    return draft, canonical_encode(encode_payload(payload))


def _captured_observation(
    task_id: str,
) -> tuple[tuple[tuple[EventDraft, bytes], ...], Coverage]:
    """Materialize the canonical OBS-001 host capture for *task_id*, exactly as the drain does."""

    fixture = cast(
        dict[str, object], load_fixture_json("canonical/OBS-001-captured-evidence.case.json")
    )
    raw_input = cast(dict[str, object], fixture["input"])
    raw = cast(dict[str, object], raw_input["envelope"])
    cursor = cast(dict[str, object], raw["cursor"])
    envelope = ObservationEnvelope(
        session_commitment=cast(str, raw["session_commitment"]),
        event_kind=cast(str, raw["event_kind"]),
        source_identity=cast(str, raw["source_identity"]),
        source=ObservationSource(cast(str, raw["source"])),
        cursor=ObservationCursor(
            cast(int, cursor["hook_seq"]),
            cast(int, cursor["session_stream_pos"]),
            cast(int, cursor["source_ordinal"]),
            cast(str, cursor["last_commitment"]),
            cast(str, cursor["mapping_version"]),
        ),
        receipt_time=Timestamp(cast(str, raw["receipt_time"])),
        structural_payload=JsonObject(cast(dict[str, JsonValue], raw["structural_payload"])),
        content_object_refs=tuple(cast(list[str], raw["content_object_refs"])),
        gap_codes=tuple(cast(list[str], raw["gap_codes"])),
    )
    manifests = tuple(
        ObservationContentManifest(
            object_id=cast(str, item["object_id"]),
            envelope_digest=cast(str, item["envelope_digest"]),
            content_kind=ObservationContentKind(cast(str, item["content_kind"])),
            part_index=cast(int, item["part_index"]),
            part_count=cast(int, item["part_count"]),
            redacted=cast(bool, item["redacted"]),
            content_digest=cast(str, item["content_digest"]),
            content_bytes=cast(int, item["content_bytes"]),
        )
        for item in cast(list[dict[str, object]], raw_input["manifests"])
    )
    batch = materialize_observation_envelope(envelope, task_id=task_id, captured_content=manifests)
    assert batch.channel is PublicationChannel.HOOK_OBSERVED
    return tuple((item.draft, item.payload_bytes) for item in batch.drafts), batch.coverage


async def _status(
    app: Application,
    started: StartInternalResult,
    seed: int,
    *,
    session: str | None = None,
    writer: str | None = None,
    evidence_filter: Mapping[str, JsonValue] | None = None,
    limit: int = 100,
    cursor: str | None = None,
    at_frontier: int | None = None,
) -> tuple[StatusInternalResult, Mapping[str, JsonValue]]:
    body: dict[str, JsonValue] = {
        **request_base(protocol_id("req_", seed)),
        "session_id": session or started.session_id,
        "writer_id": writer or started.writer_id,
        "view": "evidence",
        "limit": str(limit),
    }
    if evidence_filter is not None:
        body["filter"] = dict(evidence_filter)
    if cursor is not None:
        body["cursor"] = cursor
    if at_frontier is not None:
        body["at_frontier"] = str(at_frontier)
    internal = await app.status(StatusRequest.model_validate(body))
    assert type(internal) is StatusInternalResult
    projected = await project_case(
        app, ProjectionCase("status/evidence", ControlMethod.STATUS, body, internal), seed + 1
    )
    return internal, projected


def _rows(projected: Mapping[str, JsonValue]) -> dict[str, Mapping[str, JsonValue]]:
    page = cast(Mapping[str, JsonValue], projected["page"])
    items = cast(Sequence[Mapping[str, JsonValue]], page["items"])
    return {cast(str, item["evidence_id"]): item for item in items}


async def test_immutable_snapshot_filter_lists_native_captures_across_pages() -> None:
    """The guidance's native-capture discovery filter works through the status evidence view."""

    app, _policy = await build_projection_application(seed=9140)
    started = await _start(app, 9141)
    published, diff_id, test_id = await _publish_agent_evidence(app, started, 9150)
    frontier = published.result_frontier
    observation_writer = observation_writer_id(started.task_id, started.session_id)
    captured, captured_coverage = _captured_observation(started.task_id)
    frontier = await _append(
        app,
        started,
        seed=9160,
        expected_frontier=frontier.sequence,
        writer=observation_writer,
        author=observation_author(),
        channel=PublicationChannel.HOOK_OBSERVED,
        drafts=captured,
        coverage=captured_coverage,
    )
    second = tuple(
        _plain_evidence(9170 + offset, f"observed snapshot {offset}", strength=strength)
        for offset, strength in enumerate(
            (EvidenceImmutability.IMMUTABLE_SNAPSHOT, EvidenceImmutability.MUTABLE_REFERENCE)
        )
    )
    await _append(
        app,
        started,
        seed=9175,
        expected_frontier=frontier.sequence,
        writer=observation_writer,
        author=observation_author(),
        channel=PublicationChannel.HOOK_OBSERVED,
        drafts=second,
    )
    snapshot_filter: dict[str, JsonValue] = {"strength": "immutable_snapshot"}

    _first, first_page = await _status(app, started, 9180, evidence_filter=snapshot_filter, limit=1)
    first_rows = _rows(first_page)
    next_cursor = cast(Mapping[str, JsonValue], first_page["page"])["next_cursor"]
    assert type(next_cursor) is str
    _second, second_page = await _status(
        app, started, 9182, evidence_filter=snapshot_filter, limit=1, cursor=next_cursor
    )
    second_rows = _rows(second_page)
    assert cast(Mapping[str, JsonValue], second_page["page"])["next_cursor"] is None

    listed = {**first_rows, **second_rows}
    assert len(listed) == 2
    assert all(row["strength"] == "immutable_snapshot" for row in listed.values())
    assert diff_id not in listed and test_id not in listed
    assert protocol_id("evd_", 9170) in listed
    assert protocol_id("evd_", 9171) not in listed


def _agent_actor(name: str) -> Actor:
    return Actor(actor_id(name), ActorType.LOGICAL_AGENT, AuthorshipAssurance.SELF_ASSERTED)


def _audit(app: Application) -> MemoryPrivacyAudit:
    audit = app.privacy._audit  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
    assert type(audit) is MemoryPrivacyAudit
    return audit


async def test_agent_reads_back_its_own_evidence_under_the_default_policy() -> None:
    """codex.txt L169: the agent's own two items come back readable, host rows stay omitted."""

    app, policy = await build_projection_application(seed=9200)
    assert DataCategory.EVIDENCE_EXCERPT not in policy.agent_context_categories
    started = await _start(app, 9201)
    published, diff_id, test_id = await _publish_agent_evidence(app, started, 9210)
    captured, captured_coverage = _captured_observation(started.task_id)
    await _append(
        app,
        started,
        seed=9220,
        expected_frontier=published.result_frontier.sequence,
        writer=observation_writer_id(started.task_id, started.session_id),
        author=observation_author(),
        channel=PublicationChannel.HOOK_OBSERVED,
        drafts=captured,
        coverage=captured_coverage,
    )

    _internal, projected = await _status(
        app, started, 9230, evidence_filter={"strength": "content_digest"}
    )
    rows = _rows(projected)
    assert set(rows) == {diff_id, test_id}
    assert rows[diff_id]["description"] == _DIFF_DESCRIPTION
    assert rows[diff_id]["reference"] == "git show de58a86"
    assert rows[test_id]["description"] == _TEST_DESCRIPTION
    assert rows[test_id]["reference"] == "pytest tests -q"

    _internal, everything = await _status(app, started, 9232)
    all_rows = _rows(everything)
    hook_rows = [row for key, row in all_rows.items() if key not in {diff_id, test_id}]
    assert hook_rows, "the captured host observation must be listed"
    for row in hook_rows:
        assert row["description"] in (None, _OMITTED)
        assert row["reference"] in (None, _OMITTED)
    assert any(row["description"] == _OMITTED for row in hook_rows)

    # The projection still ran and still wrote its receipt; the receipt shows the inclusion.
    projection = cast(Mapping[str, JsonValue], everything["privacy_projection"])
    assert projection["sink"] == "agent_context"
    assert "evidence_excerpt" in cast(Sequence[str], projection["included_categories"])
    assert "evidence_excerpt" in cast(Sequence[str], projection["blocked_categories"])
    receipt_id = cast(str, projection["local_disclosure_receipt_id"])
    audit = _audit(app)
    view = await audit.get_receipt(receipt_id, PrivacyReceiptAudience.TRUSTED_LOCAL_CONTROL)
    assert view is not None
    assert DataCategory.EVIDENCE_EXCERPT in view.receipt.approved_categories
    assert DataCategory.EVIDENCE_EXCERPT in view.receipt.blocked_categories
    rows_by_receipt = [
        row
        for row in audit._state.audit.values()  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
        if row.receipt is not None and row.receipt.receipt_id == receipt_id
    ]
    assert len(rows_by_receipt) == 1
    subject = rows_by_receipt[0].subject
    assert type(subject) is AgentProjectionAuditSubject
    assert subject.provenance == (
        DisclosureProvenance.OTHER_WRITER,
        DisclosureProvenance.SELF_AUTHORED,
    )


async def test_other_writers_hook_rows_and_imports_stay_blanked() -> None:
    """Only the requester's own cooperative rows widen; every other source keeps the ceiling."""

    app, _policy = await build_projection_application(seed=9300)
    started = await _start(app, 9301)
    published, diff_id, test_id = await _publish_agent_evidence(app, started, 9310)
    frontier = published.result_frontier.sequence
    # A hook-shaped row stamped under the agent's own writer and session: the session matching is
    # not authorship, the observation stamp and channel are.
    frontier = (
        await _append(
            app,
            started,
            seed=9320,
            expected_frontier=frontier,
            writer=started.writer_id,
            author=observation_author(),
            channel=PublicationChannel.HOOK_OBSERVED,
            drafts=(
                _plain_evidence(
                    9321, "hook row under the agent writer", strength=_MUTABLE_REFERENCE
                ),
            ),
        )
    ).sequence
    # Another cooperative writer in the same task and session.
    frontier = (
        await _append(
            app,
            started,
            seed=9330,
            expected_frontier=frontier,
            writer=protocol_id("wri_", 9331),
            author=_agent_actor("delegate-writer"),
            channel=PublicationChannel.COOPERATIVE_MCP,
            drafts=(
                _plain_evidence(9332, "another writer's evidence", strength=_MUTABLE_REFERENCE),
            ),
        )
    ).sequence
    # An import appended under the agent's own writer is imported, not self-authored.
    await _append(
        app,
        started,
        seed=9340,
        expected_frontier=frontier,
        writer=started.writer_id,
        author=Actor(actor_id("local-human"), ActorType.HUMAN, AuthorshipAssurance.SELF_ASSERTED),
        channel=PublicationChannel.HUMAN_IMPORT,
        drafts=(_plain_evidence(9341, "imported transcript note", strength=_MUTABLE_REFERENCE),),
    )

    _internal, projected = await _status(app, started, 9350)
    rows = _rows(projected)
    assert rows[diff_id]["description"] == _DIFF_DESCRIPTION
    assert rows[test_id]["description"] == _TEST_DESCRIPTION
    for seed in (9321, 9332, 9341):
        row = rows[protocol_id("evd_", seed)]
        assert row["description"] == _OMITTED, seed
        assert row["reference"] == _OMITTED, seed


async def test_never_send_match_in_own_evidence_stays_redacted() -> None:
    """Self-authorship never bypasses the never-send scan on the projected bytes."""

    app, _policy = await build_projection_application(seed=9400)
    started = await _start(app, 9401)
    secret = "api_key=sk-proj-abcdefghijklmnopqrstuvwxyz012345"
    published = await _publish(
        app,
        started,
        9410,
        started.frontier,
        (
            _evidence_draft(
                9411,
                kind="test_result",
                subject="test_stdout",
                description=f"Test output leaked {secret}",
                reference="pytest tests -q",
            ),
        ),
    )
    assert published.accepted_events

    _internal, projected = await _status(app, started, 9420)
    row = _rows(projected)[protocol_id("evd_", 9411)]
    assert row["description"] == {
        "category": "evidence_excerpt",
        "omitted": True,
        "reason": "never_send_redacted",
    }
    # The clean sibling leaf of the same self-authored row is still returned.
    assert row["reference"] == "pytest tests -q"
    assert secret.encode() not in canonical_encode(cast(JsonValue, dict(projected)))


async def test_provenance_is_recomputed_per_session_and_frontier() -> None:
    """Attach opens a new session and writer: earlier rows are not self-authored for it.

    The later ``start`` attach is the event that changes the answer for the same task; the
    successor's read of the very frontier the predecessor already read must not reuse the
    predecessor's decision.
    """

    app, _policy = await build_projection_application(seed=9500)
    started = await _start(app, 9501)
    published, diff_id, _test_id = await _publish_agent_evidence(app, started, 9510)
    first = published.result_frontier.sequence

    _internal, own = await _status(app, started, 9520, at_frontier=first)
    assert _rows(own)[diff_id]["description"] == _DIFF_DESCRIPTION

    attached = await app.start(start_request(9530, title="Evidence read-back", refs=True))
    assert type(attached) is StartInternalResult
    assert attached.outcome == "attached"
    assert attached.task_id == started.task_id
    assert attached.session_id != started.session_id
    assert attached.writer_id != started.writer_id

    for seed, at_frontier in ((9540, None), (9542, first)):
        _internal, successor = await _status(
            app,
            started,
            seed,
            session=attached.session_id,
            writer=attached.writer_id,
            at_frontier=at_frontier,
        )
        row = _rows(successor)[diff_id]
        assert row["description"] == _OMITTED, at_frontier
        assert row["reference"] == _OMITTED, at_frontier

    # The successor's own publication is readable to it, at its own later frontier.
    later = await _publish(
        app,
        attached,
        9550,
        (await _status(app, attached, 9552))[0].subject_frontier,
        (
            _evidence_draft(
                9551,
                kind="test_result",
                subject="test_stdout",
                description="Successor rerun: 2036 passed.",
                reference="pytest tests -q",
            ),
        ),
    )
    _internal, successor = await _status(
        app, attached, 9560, at_frontier=later.result_frontier.sequence
    )
    rows = _rows(successor)
    assert rows[protocol_id("evd_", 9551)]["description"] == "Successor rerun: 2036 passed."
    assert rows[diff_id]["description"] == _OMITTED


async def test_author_mine_returns_exactly_the_callers_items_across_pages() -> None:
    """``filter.author=mine`` is decided from ledger authorship and survives pagination."""

    app, _policy = await build_projection_application(seed=9600)
    started = await _start(app, 9601)
    published, diff_id, test_id = await _publish_agent_evidence(app, started, 9610)
    captured, captured_coverage = _captured_observation(started.task_id)
    head = await _append(
        app,
        started,
        seed=9620,
        expected_frontier=published.result_frontier.sequence,
        writer=observation_writer_id(started.task_id, started.session_id),
        author=observation_author(),
        channel=PublicationChannel.HOOK_OBSERVED,
        drafts=captured,
        coverage=captured_coverage,
    )
    head = await _append(
        app,
        started,
        seed=9630,
        expected_frontier=head.sequence,
        writer=started.writer_id,
        author=observation_author(),
        channel=PublicationChannel.HOOK_OBSERVED,
        drafts=(_plain_evidence(9631, "hook row under the agent", strength=_MUTABLE_REFERENCE),),
    )
    head = await _append(
        app,
        started,
        seed=9640,
        expected_frontier=head.sequence,
        writer=protocol_id("wri_", 9641),
        author=_agent_actor("delegate-writer"),
        channel=PublicationChannel.COOPERATIVE_MCP,
        drafts=(_plain_evidence(9642, "another writer's row", strength=_MUTABLE_REFERENCE),),
    )
    third = await _publish(
        app,
        started,
        9650,
        head,
        (
            _evidence_draft(
                9652,
                kind="test_result",
                subject="test_stdout",
                description="Targeted rerun: 12 passed.",
                reference="pytest tests/test_tz.py -q",
            ),
        ),
    )
    own = {diff_id, test_id, protocol_id("evd_", 9652)}
    mine: dict[str, JsonValue] = {"author": "mine"}

    pages: list[Mapping[str, Mapping[str, JsonValue]]] = []
    cursor: str | None = None
    for offset in range(4):
        _internal, projected = await _status(
            app, started, 9660 + 2 * offset, evidence_filter=mine, limit=2, cursor=cursor
        )
        pages.append(_rows(projected))
        next_cursor = cast(Mapping[str, JsonValue], projected["page"])["next_cursor"]
        if next_cursor is None:
            break
        cursor = cast(str, next_cursor)
    assert [len(page) for page in pages] == [2, 1]
    listed = {key: row for page in pages for key, row in page.items()}
    assert set(listed) == own
    assert {str(row["publication_channel"]) for row in listed.values()} == {"cooperative_mcp"}
    assert listed[protocol_id("evd_", 9652)]["description"] == "Targeted rerun: 12 passed."

    # The cursor is bound to its filter: reusing it without ``author`` is refused, not widened.
    with pytest.raises(PublicOperationError):
        await _status(app, started, 9680, limit=2, cursor=cast(str, cursor))

    # Filters compose; every row in the unfiltered view names its service-stamped channel.
    _internal, digests = await _status(
        app, started, 9690, evidence_filter={"author": "mine", "strength": "content_digest"}
    )
    assert set(_rows(digests)) == own
    _internal, everything = await _status(
        app, started, 9692, at_frontier=third.result_frontier.sequence
    )
    channels = {key: str(row["publication_channel"]) for key, row in _rows(everything).items()}
    hook_row, other_row = protocol_id("evd_", 9631), protocol_id("evd_", 9642)
    assert {channels[key] for key in own} == {"cooperative_mcp"}
    assert channels[hook_row] == "hook_observed"
    assert channels[other_row] == "cooperative_mcp"
    captured_rows = set(channels) - own - {hook_row, other_row}
    assert captured_rows
    assert {channels[key] for key in captured_rows} == {"hook_observed"}

    # An attached session (new session and writer) owns none of the rows published before it.
    attached = await app.start(start_request(9695, title="Evidence read-back", refs=True))
    assert type(attached) is StartInternalResult
    _internal, successor = await _status(
        app,
        started,
        9696,
        session=attached.session_id,
        writer=attached.writer_id,
        evidence_filter=mine,
    )
    assert _rows(successor) == {}


async def test_later_redaction_withdraws_self_authored_prose_from_pinned_reads() -> None:
    """A pinned read replays its own prefix; the exemption must not re-disclose redacted prose."""

    app, _policy = await build_projection_application(seed=9700)
    started = await _start(app, 9701)
    published, diff_id, test_id = await _publish_agent_evidence(app, started, 9710)
    first = published.result_frontier.sequence
    payload = RedactionRecordedPayload(
        target_event_ids=(event_id(published.accepted_events[0].event_id),),
        target_object_ids=(),
        method=next(iter(RedactionMethod)),
        reason_category=next(iter(RedactionReasonCategory)),
        authority=actor_id("local-human"),
        remaining_gap="redacted_evidence",
    )
    await _append(
        app,
        started,
        seed=9720,
        expected_frontier=first,
        writer=started.writer_id,
        author=_agent_actor("projection-sweep"),
        channel=PublicationChannel.COOPERATIVE_MCP,
        drafts=(
            (
                EventDraft(
                    event_id(protocol_id("evt_", 9721)),
                    EventSchema("redaction_recorded", "1.0.0"),
                    timestamp_from_datetime(datetime(2026, 7, 28, 12, 5, tzinfo=UTC)),
                    (),
                    payload,
                    (),
                    (),
                ),
                canonical_encode(encode_payload(payload)),
            ),
        ),
    )

    _internal, head = await _status(app, started, 9730)
    assert diff_id not in _rows(head)
    assert _rows(head)[test_id]["description"] == _TEST_DESCRIPTION
    _internal, pinned = await _status(app, started, 9732, at_frontier=first)
    rows = _rows(pinned)
    assert rows[diff_id]["description"] == _OMITTED
    assert rows[diff_id]["reference"] == _OMITTED
    assert rows[test_id]["description"] == _TEST_DESCRIPTION
    assert _DIFF_DESCRIPTION.encode() not in canonical_encode(cast(JsonValue, dict(pinned)))


async def test_evidence_pages_build_only_the_requested_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A page builds at most ``limit + 1`` rows, however many rows the task holds (#934 review).

    The rows, their order, the cursor chain and ``author=mine`` stay exactly those of the full
    materialization (``load_projection``), which builds every readable row.
    """

    from finishup.ports.ledger import (
        EvidenceProjectionFilter,
        IdProjectionPosition,
        ProjectionQuery,
        ProjectionView,
    )
    from finishup.protocol.models import StatusEvidenceItemModel

    app, _policy = await build_projection_application(seed=9700)
    started = await _start(app, 9701)
    published, diff_id, test_id = await _publish_agent_evidence(app, started, 9710)
    others = tuple(
        _plain_evidence(9720 + offset, f"delegate row {offset}", strength=_MUTABLE_REFERENCE)
        for offset in range(60)
    )
    head = await _append(
        app,
        started,
        seed=9790,
        expected_frontier=published.result_frontier.sequence,
        writer=protocol_id("wri_", 9791),
        author=_agent_actor("delegate-writer"),
        channel=PublicationChannel.COOPERATIVE_MCP,
        drafts=others,
    )
    ledger, _objects = _ledger(app, started.task_id)
    stored = await ledger.load_projection(started.session_id, ProjectionView.EVIDENCE)
    assert stored is not None and type(stored.state) is tuple
    full = [item.model_dump() for item in stored.state if type(item) is StatusEvidenceItemModel]
    assert len(full) == 62
    own = {diff_id, test_id}

    built = {"rows": 0}
    construct: Callable[..., None] = StatusEvidenceItemModel.__init__

    def counted(self: StatusEvidenceItemModel, /, **values: object) -> None:
        built["rows"] += 1
        construct(self, **values)

    # Page items must stay exactly ``StatusEvidenceItemModel``; count its constructions instead.
    monkeypatch.setattr(StatusEvidenceItemModel, "__init__", counted)

    async def walk(
        evidence_filter: EvidenceProjectionFilter | None, limit: int
    ) -> list[dict[str, object]]:
        rows: list[dict[str, object]] = []
        position: IdProjectionPosition | None = None
        while True:
            built["rows"] = 0
            page = await ledger.query_projection(
                ProjectionQuery(
                    started.session_id,
                    "evidence",
                    evidence_filter,
                    head,
                    limit,
                    position,
                    None,
                    started.writer_id,
                )
            )
            assert built["rows"] <= limit + 1
            assert len(page.item_sources) == len(page.items)
            rows.extend(cast(StatusEvidenceItemModel, item).model_dump() for item in page.items)
            if page.next_position is None:
                return rows
            assert type(page.next_position) is IdProjectionPosition
            assert page.next_position.last_id == rows[-1]["evidence_id"]
            position = page.next_position

    assert await walk(None, 7) == full
    assert await walk(EvidenceProjectionFilter(None, None, True, "mine"), 1) == [
        row for row in full if row["evidence_id"] in own
    ]

    # A prefix whose ``source_frontier`` indexes miss falls back to one scan with the same rows.
    from finishup.adapters.memory import ledger as ledger_module

    state = ledger._state  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
    evidence_rows = ledger_module._evidence_rows  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
    indexed = [
        (key, row.event_id) for key, _, row in evidence_rows(state.projection, state.records)
    ]
    scanned = [
        (key, row.event_id)
        for key, _, row in evidence_rows(state.projection, tuple(reversed(state.records)))
    ]
    assert scanned == indexed
    assert [key for key, _ in indexed] == [row["evidence_id"] for row in full]
