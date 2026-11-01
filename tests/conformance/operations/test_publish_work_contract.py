"""Conformance tests for the public publish-work application contract."""

from __future__ import annotations

import uuid
from typing import cast

import pytest
from pydantic import ValidationError

from builders.replay import replay_records
from finishup.application.publish_work import (
    Application,
    _draft_pointer,  # pyright: ignore[reportPrivateUsage]
    prepare_publication,
)
from finishup.domain.events import EventPayload, encode_payload
from finishup.protocol.coverage import PublicationChannel
from finishup.protocol.errors import PublicErrorCode, PublicOperationError
from finishup.protocol.models import PublishWorkRequestModel

_ORDINARY = frozenset(
    {
        "plan_published",
        "obligation_published",
        "assignment_recorded",
        "decision_recorded",
        "action_recorded",
        "result_recorded",
        "evidence_recorded",
        "claim_recorded",
        "plan_revised",
    }
)
_RESERVED = frozenset(
    {
        "session_opened",
        "session_resumed",
        "finding_recorded",
        "check_recorded",
        "response_recorded",
        "receipt_recorded",
        "redaction_recorded",
    }
)


class _App:
    def __init__(self, *, trusted_import: bool = False) -> None:
        self.trusted_import = trusted_import

    def authorizes_import_publication(self, request: PublishWorkRequestModel) -> bool:
        del request
        return self.trusted_import


def _request_for_record(family: str) -> PublishWorkRequestModel:
    record = next(row for row in replay_records("all-event-families") if row.schema.name == family)
    assert record.payload is not None
    return PublishWorkRequestModel.model_validate(
        {
            "protocol_version": "0.1",
            "schema_version": "1.0.0",
            "request_id": "req_00000000-0000-4000-8000-000000000301",
            "session_id": record.session_id,
            "writer_id": record.writer.writer_id,
            "expected_frontier": {"sequence": "0", "head_digest": "genesis"},
            "event_drafts": (
                {
                    "event_id": record.event_id,
                    "schema": {
                        "name": record.schema.name,
                        "version": record.schema.version,
                    },
                    "occurred_at": record.occurred_at.wire,
                    "causal_parents": record.causal_parents,
                    "payload": encode_payload(cast(EventPayload, record.payload)),
                    "artifact_refs": record.artifact_refs,
                    "evidence_refs": record.evidence_refs,
                },
            ),
            "actor": {"actor_id": "harness:test", "actor_type": "harness"},
            "client": {
                "kind": "test_client",
                "version": "0.1.0",
                "integration": "local_cli",
            },
        }
    )


@pytest.mark.parametrize("family", sorted(_ORDINARY, key=str.encode))
def test_ordinary_channel_admits_exact_cooperative_families(family: str) -> None:
    request = _request_for_record(family)

    prepared = prepare_publication(
        request,
        channel=PublicationChannel.LOCAL_CLI,
        app=cast(Application, _App()),
    )

    assert prepared.drafts[0].draft.schema.name == family
    assert prepared.drafts[0].projection_status == "projected"


@pytest.mark.parametrize("family", sorted(_RESERVED, key=str.encode))
def test_ordinary_channel_rejects_reserved_families(family: str) -> None:
    request = _request_for_record(family)

    with pytest.raises(PublicOperationError) as caught:
        prepare_publication(
            request,
            channel=PublicationChannel.LOCAL_CLI,
            app=cast(Application, _App()),
        )

    assert caught.value.code is PublicErrorCode.EVENT_INVALID
    assert caught.value.safe_details == {
        "continuation": "input_correction_new_identity",
        "field": "/event_drafts/0/schema",
        "reason_code": "event_family_not_admitted",
    }


def _action_drafts(count: int) -> tuple[dict[str, object], ...]:
    values: list[dict[str, object]] = []
    for index in range(1, count + 1):
        event_uuid = uuid.UUID(int=10_000 + index, version=4)
        action_uuid = uuid.UUID(int=20_000 + index, version=4)
        values.append(
            {
                "event_id": f"evt_{event_uuid}",
                "schema": {"name": "action_recorded", "version": "1.0.0"},
                "occurred_at": "2026-07-19T12:00:00.000Z",
                "causal_parents": (),
                "payload": {
                    "action_id": f"act_{action_uuid}",
                    "action_kind": "other",
                    "description": f"bounded action {index}",
                },
                "artifact_refs": (),
                "evidence_refs": (),
            }
        )
    return tuple(values)


def _bounded_request(count: int) -> PublishWorkRequestModel:
    return PublishWorkRequestModel.model_validate(
        {
            "protocol_version": "0.1",
            "schema_version": "1.0.0",
            "request_id": "req_00000000-0000-4000-8000-000000000302",
            "session_id": "ses_00000000-0000-4000-8000-000000000303",
            "writer_id": "wri_00000000-0000-4000-8000-000000000304",
            "expected_frontier": None,
            "event_drafts": _action_drafts(count),
            "actor": {"actor_id": "harness:test", "actor_type": "harness"},
            "client": {
                "kind": "test_client",
                "version": "0.1.0",
                "integration": "local_cli",
            },
        }
    )


@pytest.mark.parametrize("count", (1, 100))
def test_batch_boundaries_one_and_one_hundred_are_admitted(count: int) -> None:
    request = _bounded_request(count)
    prepared = prepare_publication(
        request,
        channel=PublicationChannel.LOCAL_CLI,
        app=cast(Application, _App()),
    )
    assert len(prepared.drafts) == count


def test_batch_boundary_one_hundred_one_is_rejected_by_public_model() -> None:
    with pytest.raises(ValidationError):
        _bounded_request(101)


def test_state_sensitive_family_requires_expected_frontier() -> None:
    request = _request_for_record("plan_published").model_copy(update={"expected_frontier": None})
    with pytest.raises(PublicOperationError) as caught:
        prepare_publication(
            request,
            channel=PublicationChannel.LOCAL_CLI,
            app=cast(Application, _App()),
        )
    assert caught.value.code is PublicErrorCode.EVENT_INVALID


def test_unsorted_causal_parents_reject_as_event_invalid_unsorted_set_field() -> None:
    base = _request_for_record("plan_published")
    draft = dict(cast(dict[str, object], base.event_drafts[0]))
    draft["causal_parents"] = (
        "evt_00000000-0000-4000-8000-000000000002",
        "evt_00000000-0000-4000-8000-000000000001",
    )
    request = base.model_copy(update={"event_drafts": (draft,)})

    with pytest.raises(PublicOperationError) as caught:
        prepare_publication(
            request,
            channel=PublicationChannel.LOCAL_CLI,
            app=cast(Application, _App()),
        )

    assert caught.value.code is PublicErrorCode.EVENT_INVALID
    # The draft is located even when the rejection comes from a whole-draft invariant rather
    # than a single field.
    assert caught.value.safe_details == {
        "continuation": "sorted_set_required",
        "field": "/event_drafts/0",
        "reason_code": "unsorted_set_field",
    }


def test_unsorted_payload_set_field_is_located_by_name() -> None:
    """A rejected reference list names itself, so the fix does not need guesswork.

    Regression for the 2026-07-30 dogfood: `/event_drafts/N/payload` alone left an agent
    choosing between `supporting_refs` and `obligation_refs` by trial and error.
    """

    base = _request_for_record("claim_recorded")
    draft = dict(cast(dict[str, object], base.event_drafts[0]))
    payload = dict(cast(dict[str, object], draft["payload"]))
    payload["supporting_refs"] = (
        "evd_00000000-0000-4000-8000-000000000002",
        "evd_00000000-0000-4000-8000-000000000001",
    )
    draft["payload"] = payload
    request = base.model_copy(update={"event_drafts": (draft,)})

    with pytest.raises(PublicOperationError) as caught:
        prepare_publication(
            request,
            channel=PublicationChannel.LOCAL_CLI,
            app=cast(Application, _App()),
        )

    assert caught.value.code is PublicErrorCode.EVENT_INVALID
    assert caught.value.safe_details == {
        "continuation": "sorted_set_required",
        "field": "/event_drafts/0/payload/supporting_refs",
        "reason_code": "unsorted_set_field",
    }
    assert "ascending ASCII" in caught.value.message


def test_unsorted_obligation_ids_name_the_field_and_the_ascii_rule() -> None:
    """Issue #579: assignment obligation_ids in authoring order is the live dogfood shape."""

    base = _request_for_record("assignment_recorded")
    draft = dict(cast(dict[str, object], base.event_drafts[0]))
    payload = dict(cast(dict[str, object], draft["payload"]))
    payload["obligation_ids"] = (
        "obl_00000000-0000-4000-8000-000000000002",
        "obl_00000000-0000-4000-8000-000000000001",
    )
    draft["payload"] = payload
    request = base.model_copy(update={"event_drafts": (draft,)})

    with pytest.raises(PublicOperationError) as caught:
        prepare_publication(
            request,
            channel=PublicationChannel.LOCAL_CLI,
            app=cast(Application, _App()),
        )

    assert caught.value.code is PublicErrorCode.EVENT_INVALID
    assert caught.value.safe_details == {
        "continuation": "sorted_set_required",
        "field": "/event_drafts/0/payload/obligation_ids",
        "reason_code": "unsorted_set_field",
    }
    assert "ascending ASCII" in caught.value.message
    assert "uniqueItems" in caught.value.message


def test_payload_pointer_admits_only_registered_field_names() -> None:
    """An unregistered field name degrades to the payload pointer rather than echoing itself."""

    assert (
        _draft_pointer(0, "payload", "supporting_refs") == "/event_drafts/0/payload/supporting_refs"
    )
    assert _draft_pointer(0, "payload", "../../etc/passwd") == "/event_drafts/0/payload"
    assert _draft_pointer(0, "payload", None) == "/event_drafts/0/payload"
    # Only the payload is descended into; every other subfield stays one level deep.
    assert _draft_pointer(0, "schema", "supporting_refs") == "/event_drafts/0/schema"


def _unknown_import_request() -> PublishWorkRequestModel:
    return PublishWorkRequestModel.model_validate(
        {
            "protocol_version": "0.1",
            "schema_version": "1.0.0",
            "request_id": "req_00000000-0000-4000-8000-000000000305",
            "session_id": "ses_00000000-0000-4000-8000-000000000306",
            "writer_id": "wri_00000000-0000-4000-8000-000000000307",
            "expected_frontier": None,
            "event_drafts": (
                {
                    "event_id": "evt_00000000-0000-4000-8000-000000000308",
                    "schema": {"name": "codex_jsonl_observation", "version": "1.0.0"},
                    "occurred_at": "2026-07-19T12:00:00.000Z",
                    "causal_parents": (),
                    "payload": {"opaque": "preserve exactly", "ordinal": 1},
                    "artifact_refs": (),
                    "evidence_refs": (),
                },
            ),
            "actor": {"actor_id": "harness:import", "actor_type": "importer"},
            "client": {
                "kind": "importer",
                "version": "0.1.0",
                "integration": "codex_jsonl_import",
            },
        }
    )


def test_unknown_event_requires_trusted_import_authority_and_adds_gap() -> None:
    request = _unknown_import_request()
    with pytest.raises(PublicOperationError):
        prepare_publication(
            request,
            channel=PublicationChannel.CODEX_JSONL_IMPORT,
            app=cast(Application, _App()),
        )

    prepared = prepare_publication(
        request,
        channel=PublicationChannel.CODEX_JSONL_IMPORT,
        app=cast(Application, _App(trusted_import=True)),
    )
    assert prepared.drafts[0].projection_status == "unknown_unprojected"
    assert "unknown_event_schema_preserved" in prepared.coverage.known_gaps
    assert prepared.author.assurance.value == "harness_observed"
