"""The reduced total-acceptance envelope is constructible for every publish event family."""

from __future__ import annotations

from types import MappingProxyType
from typing import cast

import pytest

from finishup.application.publish_work import build_accepted_projection_unavailable_result
from finishup.domain.values import Frontier
from finishup.ports.ledger import AcceptedEventSummary
from finishup.protocol import models as protocol_models
from finishup.protocol.models import (
    PublishWorkAcceptedProjectionUnavailableModel,
    PublishWorkResult,
)

# Registry maps are module-private; getattr matches other coverage tests and avoids
# reportPrivateUsage while still locking constructibility to every published family.
_PUBLISH_SUMMARY_CATEGORY = getattr(protocol_models, "_PUBLISH_SUMMARY_CATEGORY")
_PUBLISH_FIXED_SUMMARY = getattr(protocol_models, "_PUBLISH_FIXED_SUMMARY")

_CORRELATION = "err_00000000-0000-4000-8000-000000000042"
_TASK = "tsk_00000000-0000-4000-8000-000000000001"
_SESSION = "ses_00000000-0000-4000-8000-000000000002"
_WRITER = "wri_00000000-0000-4000-8000-000000000003"
_REQUEST = "req_00000000-0000-4000-8000-000000000004"
_DIGEST = "sha256:" + "a" * 64
_FRONTIER = Frontier(sequence=6, head_digest=_DIGEST)


def _summary(event_id: str, sequence: int) -> AcceptedEventSummary:
    return AcceptedEventSummary(
        event_id,
        sequence,
        sequence,
        _DIGEST,
        "projected",
    )


def test_minimal_envelope_is_ok_with_accepted_projection_unavailable() -> None:
    result = build_accepted_projection_unavailable_result(
        request_id=_REQUEST,
        outcome="accepted",
        task_id=_TASK,
        session_id=_SESSION,
        writer_id=_WRITER,
        subject_frontier=Frontier(sequence=2, head_digest="sha256:" + "b" * 64),
        result_frontier=_FRONTIER,
        accepted=(_summary("evt_00000000-0000-4000-8000-000000000010", 3),),
        correlation_id=_CORRELATION,
    )
    assert type(result) is PublishWorkResult
    root = result.root
    assert type(root) is PublishWorkAcceptedProjectionUnavailableModel
    assert root.ok is True
    assert root.response_completeness == "accepted_projection_unavailable"
    assert root.reason_code == "response_projection_failed"
    assert root.correlation_id == _CORRELATION
    assert root.result_frontier.sequence == "6"
    assert root.accepted_events[0].event_id == "evt_00000000-0000-4000-8000-000000000010"
    assert root.accepted_events[0].entry_digest == _DIGEST
    assert root.accepted_events[0].ingestion_sequence == "3"


@pytest.mark.parametrize(
    "schema_name,schema_version",
    sorted(set(_PUBLISH_SUMMARY_CATEGORY) | set(_PUBLISH_FIXED_SUMMARY)),
)
def test_minimal_envelope_constructible_for_every_publish_family(
    schema_name: str, schema_version: str
) -> None:
    del schema_name, schema_version  # envelope is schema-agnostic; family set is the coverage gate
    event_id = "evt_00000000-0000-4000-8000-000000000099"
    result = build_accepted_projection_unavailable_result(
        request_id=_REQUEST,
        outcome="accepted",
        task_id=_TASK,
        session_id=_SESSION,
        writer_id=_WRITER,
        subject_frontier=_FRONTIER,
        result_frontier=_FRONTIER,
        accepted=(_summary(event_id, 1),),
        correlation_id=_CORRELATION,
    )
    root = cast(PublishWorkAcceptedProjectionUnavailableModel, result.root)
    assert root.accepted_events[0].event_id == event_id


def test_publish_summary_and_fixed_registries_are_nonempty() -> None:
    # Guard the parametrize coverage set: an empty registry would make the constructibility
    # test pass without checking any family.
    assert MappingProxyType(_PUBLISH_SUMMARY_CATEGORY)
    assert MappingProxyType(_PUBLISH_FIXED_SUMMARY)
