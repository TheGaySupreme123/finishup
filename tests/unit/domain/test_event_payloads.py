"""Contract tests for event payloads, codecs, and accepted record views."""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import textwrap
from collections.abc import Callable, Mapping
from copy import deepcopy
from dataclasses import FrozenInstanceError, fields, is_dataclass, replace
from hashlib import sha256
from itertools import product
from pathlib import Path
from typing import Any, Final, cast

import pytest
from hypothesis import example, given, settings
from hypothesis import strategies as st
from hypothesis.strategies import SearchStrategy

from finishup.domain.coordination import CoordinationDisposition, OverlapKind
from finishup.domain.events import (
    CLAIM_SCHEMA_VERSION,
    EVENT_FAMILIES,
    EVIDENCE_SCHEMA_VERSION,
    PAYLOAD_TYPES,
    SCHEMA_VERSION,
    AcceptedEvent,
    ActionKind,
    ActionRecordedPayload,
    CheckMode,
    CheckRecordedPayload,
    ClaimKind,
    ClaimRecordedPayload,
    ClaimRecordedPayloadV1_1,
    ClientKind,
    CoordinationContextRecordedPayload,
    CoordinationDispositionRecordedPayload,
    CoordinationObligationDeclaredPayload,
    DelegationDeclaredPayload,
    EventDraft,
    EventPayload,
    EventSchema,
    EvidenceContentAvailability,
    EvidenceDigestBinding,
    EvidenceDigestProvenance,
    EvidenceDigestSubject,
    EvidenceKind,
    EvidenceRecordedPayload,
    FindingRecordedPayload,
    IntegrationKind,
    LedgerChain,
    LineageOrigin,
    NoObligationsReason,
    ObligationChange,
    ObligationChangeKind,
    ObligationStatus,
    PayloadRef,
    PlanPublishedPayload,
    PlanRevisedPayload,
    PolicyVersion,
    ProjectionLocator,
    RedactionMethod,
    RedactionReasonCategory,
    RedactionState,
    RequestedItem,
    RequestedItemKind,
    RequestedItemRole,
    ResponseRecordedPayload,
    ResultOutcome,
    ResultRecordedPayload,
    RuntimeProfile,
    SessionOpenedPayload,
    UnknownEvent,
    WritePolicy,
    WriterChain,
    accepted_record_digest_preimage,
    accepted_record_to_json,
    decode_payload,
    encode_payload,
    media_type_for,
    normalize_payload_json,
)
from finishup.domain.findings import (
    Finding,
    ResponseDisposition,
    RuntimeAttemptEvidence,
    RuntimeTokenUsage,
    SamplingParams,
    SemanticDispatchKind,
    SemanticProvenance,
    WaiverScope,
)
from finishup.domain.values import (
    Actor,
    ActorType,
    JsonObject,
    SubjectStateRef,
    actor_id,
    claim_id,
    event_id,
    evidence_id,
    freeze_json,
    object_id,
    obligation_id,
    request_id,
    result_id,
    session_id,
    task_id,
    timestamp_from_string,
    writer_id,
)
from finishup.protocol.canonical import JsonValue as CanonicalJsonValue
from finishup.protocol.canonical import canonical_digest, canonical_encode, entry_digest
from finishup.protocol.coverage import (
    AuthorshipAssurance,
    EvidenceImmutability,
    PublicationChannel,
    coverage_from_json,
)
from finishup.protocol.errors import ProtocolValueError
from finishup.protocol.models import (
    CheckPolicyExecutionModel,
    CheckScopeModel,
    SemanticReason,
    SemanticStatus,
)
from finishup.protocol.schemas import validate_schema_instance

_FIXTURE_PATH = Path(__file__).parents[3] / "fixtures" / "replay" / "all-event-families.case.json"
_LINEAGE_FIXTURE_PATH = (
    Path(__file__).parents[3] / "fixtures" / "replay" / "lineage-event-families.case.json"
)
_DIGEST = "sha256:" + "1" * 64
_COMMITMENT = "hmac-sha256:" + "2" * 64
_SRC_ROOT: Final = Path(__file__).parents[3] / "src"
_EVENT_MATRIX_SCRIPT: Final = textwrap.dedent(
    """
    import base64
    import json
    import sys
    import time
    from hashlib import sha256
    from pathlib import Path

    source_root = Path(sys.argv[1])
    sys.path.insert(0, str(source_root))
    if hasattr(time, "tzset"):
        time.tzset()

    from finishup.domain.events import EventSchema, decode_payload, encode_payload
    from finishup.domain.values import freeze_json
    from finishup.protocol.canonical import canonical_encode

    rows = json.loads(base64.b64decode(sys.argv[2]).decode("utf-8"))
    encoded = []
    for row in rows:
        schema = EventSchema(row["schema"]["name"], row["schema"]["version"])
        payload = decode_payload(schema, freeze_json(row["payload"]))
        encoded.append(encode_payload(payload))
    print(sha256(canonical_encode(tuple(encoded))).hexdigest())
    """
).strip()


def _fixture_rows(path: Path) -> tuple[dict[str, Any], ...]:
    document = cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))
    raw_input = cast(dict[str, Any], document["input"])
    rows = cast(list[dict[str, Any]], raw_input["accepted_entries"])
    return tuple(deepcopy(rows))


_ROWS = _fixture_rows(_FIXTURE_PATH)
_LINEAGE_ROWS = _fixture_rows(_LINEAGE_FIXTURE_PATH)
_ROW_BY_FAMILY = {
    cast(str, cast(dict[str, Any], row["envelope"])["schema"]["name"]): row
    for row in (*_ROWS, *_LINEAGE_ROWS)
}
_FIXTURE_FAMILIES: Final[tuple[str, ...]] = tuple(
    family for family in EVENT_FAMILIES if family in _ROW_BY_FAMILY
)


def _assert_reason(reason: str, operation: Callable[[], object]) -> None:
    with pytest.raises(ProtocolValueError) as caught:
        operation()
    assert caught.value.reason_code == reason


def _coordination_context_wire() -> dict[str, Any]:
    return {
        "detection_id": "evt_30000003-0000-4000-8000-000000000101",
        "project_id": "prj_30000003-0000-4000-8000-000000000102",
        "membership_generation": "3",
        "left_task_id": "tsk_30000003-0000-4000-8000-000000000103",
        "right_task_id": "tsk_30000003-0000-4000-8000-000000000104",
        "recipient_task_id": "tsk_30000003-0000-4000-8000-000000000103",
        "counterpart_task_id": "tsk_30000003-0000-4000-8000-000000000104",
        "source_task_id": "tsk_30000003-0000-4000-8000-000000000104",
        "overlap_kind": "integration",
        "resource_identities": [
            "sha256:" + "1" * 64,
            "sha256:" + "2" * 64,
        ],
        "resource_count": "2",
        "source_repository_commitment": "hmac-sha256:" + "3" * 64,
        "source_workspace_commitment": "hmac-sha256:" + "4" * 64,
        "source_route_generation": "7",
        "source_attributable_paths": True,
        "context_digest": "sha256:" + "5" * 64,
    }


def _coordination_disposition_wire() -> dict[str, Any]:
    return {
        "detection_id": "evt_30000003-0000-4000-8000-000000000101",
        "project_id": "prj_30000003-0000-4000-8000-000000000102",
        "membership_generation": "3",
        "recipient_task_id": "tsk_30000003-0000-4000-8000-000000000103",
        "obligation_id": "obl_30000003-0000-4000-8000-000000000105",
        "disposition": "shared_work",
        "evidence_refs": ["evd_30000003-0000-4000-8000-000000000106"],
    }


def _coordination_obligation_declared_wire() -> dict[str, Any]:
    return {
        "detection_id": "evt_30000003-0000-4000-8000-000000000101",
        "project_id": "prj_30000003-0000-4000-8000-000000000102",
        "membership_generation": "3",
        "recipient_task_id": "tsk_30000003-0000-4000-8000-000000000103",
        "obligation_id": "obl_30000003-0000-4000-8000-000000000105",
    }


def _schema_for(row: Mapping[str, Any]) -> EventSchema:
    envelope = cast(dict[str, Any], row["envelope"])
    schema = cast(dict[str, str], envelope["schema"])
    return EventSchema(schema["name"], schema["version"])


def _decode_row(row: Mapping[str, Any]) -> object:
    return decode_payload(_schema_for(row), freeze_json(row["payload"]))


def _fixture_ids(prefix: str, count: int) -> tuple[str, ...]:
    return tuple(
        f"{prefix}{index:08x}-0000-4000-8000-{index:012x}" for index in range(1, count + 1)
    )


_TEXT_FIELD_BY_FAMILY: Final[Mapping[str, str]] = {
    "session_opened": "task_title",
    "session_resumed": "client_version",
    "plan_published": "summary",
    "obligation_published": "description",
    "assignment_recorded": "scope_description",
    "decision_recorded": "rationale",
    "action_recorded": "description",
    "result_recorded": "summary",
    "evidence_recorded": "description",
    "claim_recorded": "statement",
    "plan_revised": "summary",
    "finding_recorded": "summary",
    "response_recorded": "reason",
    "redaction_recorded": "remaining_gap",
}
_GENERATED_TEXT: Final[SearchStrategy[str]] = st.one_of(
    st.sampled_from(("é", "e\u0301", "שׁ", "😀", "x" * 8_192)),
    st.text(
        st.characters(codec="utf-8", blacklist_characters="\x00"),
        min_size=1,
        max_size=32,
    ),
)


def _generated_payload(family: str, text_value: str, integer_value: int) -> EventPayload:
    payload = cast(EventPayload, _decode_row(_ROW_BY_FAMILY[family]))
    if family in {
        "delegation_declared",
        "delegation_cancelled",
        "child_accepted",
        "child_rejected",
        "child_written_off",
        "child_dependencies_recorded",
        "work_closed",
        "work_abandoned",
        "work_cancelled",
        "work_written_off",
        "coordination_obligation_declared",
    }:
        # Lineage payloads are intentionally all structural and closed.  Their golden rows already
        # exercise the accepted values; retain those values while this matrix varies text and
        # integer inputs for the pre-existing prose-bearing payload families.
        return payload
    if family == "check_recorded":
        changes: dict[str, object] = {"suppressed_count": integer_value}
    elif family == "receipt_recorded":
        changes = {"receipt_digest": canonical_digest(text_value)}
    else:
        maximum = (
            256
            if family == "session_resumed"
            else 4_096
            if family
            in {
                "response_recorded",
                "redaction_recorded",
            }
            else 8_192
        )
        changes = {_TEXT_FIELD_BY_FAMILY[family]: text_value[:maximum]}
    return cast(EventPayload, cast(Any, replace)(payload, **changes))


def _fixed_generated_payloads() -> tuple[tuple[EventSchema, EventPayload], ...]:
    unicode_values = ("x" * 8_192, "é", "e\u0301", "שׁ", "😀")
    return tuple(
        (
            _schema_for(_ROW_BY_FAMILY[family]),
            _generated_payload(
                family,
                unicode_values[index % len(unicode_values)],
                9_007_199_254_740_991,
            ),
        )
        for index, family in enumerate(_FIXTURE_FAMILIES)
    )


@pytest.mark.parametrize("family", _FIXTURE_FAMILIES)
def test_each_event_family_validates_required_and_optional_fields(family: str) -> None:
    row = _ROW_BY_FAMILY[family]
    schema = _schema_for(row)
    payload = decode_payload(schema, freeze_json(row["payload"]))
    encoded = encode_payload(payload)
    assert canonical_encode(encoded) == canonical_encode(cast(CanonicalJsonValue, row["payload"]))
    assert decode_payload(schema, encoded) == payload
    validate_schema_instance(
        schema.name.replace("_", "-"),
        schema.version,
        cast(CanonicalJsonValue, encoded),
    )


_REQUIRED_FIELD_BY_FAMILY = {
    "session_opened": "task_title",
    "session_resumed": "resumed_frontier",
    "plan_published": "obligation_refs",
    "obligation_published": "obligation_id",
    "assignment_recorded": "assignee_actor_id",
    "decision_recorded": "authority",
    "action_recorded": "action_id",
    "result_recorded": "result_id",
    "evidence_recorded": "evidence_id",
    "claim_recorded": "supporting_refs",
    "plan_revised": "obligation_changes",
    "finding_recorded": "finding_id",
    "response_recorded": "finding_frontier",
    "redaction_recorded": "target_event_ids",
    "check_recorded": "scope",
    "receipt_recorded": "receipt_id",
    "delegation_declared": "child_task_id",
    "delegation_cancelled": "child_task_id",
    "child_accepted": "child_task_id",
    "child_rejected": "child_task_id",
    "child_written_off": "child_task_id",
    "child_dependencies_recorded": "children",
    "coordination_obligation_declared": "detection_id",
    "work_abandoned": "service_stamped",
}


@pytest.mark.parametrize("family", _FIXTURE_FAMILIES)
def test_each_known_family_rejects_one_missing_required_field(family: str) -> None:
    if family not in _REQUIRED_FIELD_BY_FAMILY:
        pytest.skip("family has no required payload fields beyond the closed empty object")
    row = _ROW_BY_FAMILY[family]
    wire = deepcopy(cast(dict[str, Any], row["payload"]))
    del wire[_REQUIRED_FIELD_BY_FAMILY[family]]
    expected = (
        "finding_json_shape_invalid" if family == "finding_recorded" else "missing_payload_field"
    )
    _assert_reason(
        expected,
        lambda: decode_payload(_schema_for(row), freeze_json(wire)),
    )


def test_event_payloads_are_frozen() -> None:
    for row in (*_ROWS, *_LINEAGE_ROWS):
        payload = _decode_row(row)
        assert is_dataclass(payload)
        field_name = fields(payload)[0].name
        with pytest.raises(FrozenInstanceError):
            setattr(payload, field_name, object())


def test_boundary_model_conversion_normalizes_optional_fields() -> None:
    row = _ROW_BY_FAMILY["plan_published"]
    absent = deepcopy(cast(dict[str, Any], row["payload"]))
    absent.pop("scope_exclusions", None)
    explicit_empty = deepcopy(absent)
    explicit_empty["scope_exclusions"] = []
    schema = _schema_for(row)
    assert decode_payload(schema, freeze_json(absent)) == decode_payload(
        schema, freeze_json(explicit_empty)
    )
    normalized = normalize_payload_json(schema, freeze_json(explicit_empty))
    assert "scope_exclusions" not in cast(Mapping[str, object], normalized)
    assert normalize_payload_json(schema, normalized) == normalized


@pytest.mark.parametrize("reason", tuple(NoObligationsReason))
@pytest.mark.parametrize("family", ("plan_published", "plan_revised"))
def test_no_obligations_reason_values_round_trip(
    family: str,
    reason: NoObligationsReason,
) -> None:
    row = _ROW_BY_FAMILY[family]
    wire = deepcopy(cast(dict[str, Any], row["payload"]))
    if family == "plan_published":
        wire["obligation_refs"] = []
    else:
        wire["obligation_changes"] = []
    wire["no_obligations_reason"] = reason.value

    payload = decode_payload(_schema_for(row), freeze_json(wire))
    assert isinstance(payload, PlanPublishedPayload | PlanRevisedPayload)
    assert payload.no_obligations_reason is reason
    encoded = encode_payload(payload)
    assert cast(Mapping[str, object], encoded)["no_obligations_reason"] == reason.value
    assert decode_payload(_schema_for(row), encoded) == payload


@pytest.mark.parametrize("family", ("plan_published", "plan_revised"))
def test_unknown_no_obligations_reason_fails_closed(family: str) -> None:
    row = _ROW_BY_FAMILY[family]
    wire = deepcopy(cast(dict[str, Any], row["payload"]))
    wire["no_obligations_reason"] = "caller_controlled_reason"
    _assert_reason(
        "invalid_event_enum",
        lambda: decode_payload(_schema_for(row), freeze_json(wire)),
    )


def test_omitted_no_obligations_reason_preserves_existing_canonical_event_bytes() -> None:
    for family in ("plan_published", "plan_revised"):
        row = _ROW_BY_FAMILY[family]
        original = freeze_json(row["payload"])
        payload = decode_payload(_schema_for(row), original)
        assert isinstance(payload, PlanPublishedPayload | PlanRevisedPayload)
        assert payload.no_obligations_reason is None
        assert canonical_encode(encode_payload(payload)) == canonical_encode(original)

        record = _accepted_from_row(row)
        original_envelope = freeze_json(row["envelope"])
        assert canonical_encode(accepted_record_to_json(record)) == canonical_encode(
            original_envelope
        )
        original_preimage = dict(cast(Mapping[str, Any], row["envelope"]))
        original_preimage.pop("entry_digest")
        assert canonical_encode(accepted_record_digest_preimage(record)) == canonical_encode(
            freeze_json(original_preimage)
        )


_OPTIONAL_FIELDS: Final = (
    ("session_opened", "external_ref"),
    ("session_opened", "workspace_ref"),
    ("plan_published", "scope_exclusions"),
    ("plan_published", "no_obligations_reason"),
    ("obligation_published", "acceptance_criteria"),
    ("obligation_published", "requested_items"),
    ("obligation_published", "source_refs"),
    ("obligation_published", "resolution_evidence_refs"),
    ("assignment_recorded", "write_policy"),
    ("assignment_recorded", "handoff_of"),
    ("decision_recorded", "alternatives"),
    ("decision_recorded", "affected_obligation_ids"),
    ("decision_recorded", "supersedes_event_id"),
    ("action_recorded", "command"),
    ("action_recorded", "subject_state"),
    ("action_recorded", "obligation_refs"),
    ("action_recorded", "attempted_items"),
    ("result_recorded", "exit_status"),
    ("result_recorded", "summary"),
    ("result_recorded", "subject_state"),
    ("result_recorded", "evidence_refs"),
    ("evidence_recorded", "reference"),
    ("evidence_recorded", "captured_object_id"),
    ("evidence_recorded", "content_digest"),
    ("evidence_recorded", "description"),
    ("evidence_recorded", "subject_state"),
    ("claim_recorded", "subject_state"),
    ("claim_recorded", "obligation_refs"),
    ("claim_recorded", "disputes_refs"),
    ("plan_revised", "no_obligations_reason"),
    ("response_recorded", "reason"),
    ("response_recorded", "waiver_scope"),
    ("response_recorded", "waiver_expiry"),
    ("response_recorded", "evidence_refs"),
    ("check_recorded", "semantic_provenance"),
)


@pytest.mark.parametrize(("family", "field_name"), _OPTIONAL_FIELDS)
def test_present_null_optional_fields_fail_closed(family: str, field_name: str) -> None:
    row = _ROW_BY_FAMILY[family]
    wire = deepcopy(cast(dict[str, Any], row["payload"]))
    wire[field_name] = None
    _assert_reason(
        "invalid_event_value_type",
        lambda: decode_payload(_schema_for(row), freeze_json(wire)),
    )


def test_nested_and_finding_optional_nulls_fail_closed() -> None:
    action_row = _ROW_BY_FAMILY["action_recorded"]
    action_wire = deepcopy(cast(dict[str, Any], action_row["payload"]))
    action_wire["subject_state"] = {"described_state": None}
    _assert_reason(
        "invalid_event_value_type",
        lambda: decode_payload(_schema_for(action_row), freeze_json(action_wire)),
    )

    revision_row = _ROW_BY_FAMILY["plan_revised"]
    revision_wire = deepcopy(cast(dict[str, Any], revision_row["payload"]))
    changes = cast(list[dict[str, Any]], revision_wire["obligation_changes"])
    changes[0]["reason"] = None
    _assert_reason(
        "invalid_event_value_type",
        lambda: decode_payload(_schema_for(revision_row), freeze_json(revision_wire)),
    )

    finding_row = _ROW_BY_FAMILY["finding_recorded"]
    finding_wire = deepcopy(cast(dict[str, Any], finding_row["payload"]))
    finding_wire["provenance"] = None
    _assert_reason(
        "finding_json_shape_invalid",
        lambda: decode_payload(_schema_for(finding_row), freeze_json(finding_wire)),
    )


def test_exact_schema_pair_dispatch_and_unknown_boundary() -> None:
    assert tuple(dict.fromkeys(schema.name for schema in PAYLOAD_TYPES)) == EVENT_FAMILIES
    assert {schema.version for schema in PAYLOAD_TYPES if schema.name == "evidence_recorded"} == {
        SCHEMA_VERSION,
        "1.1.0",
        EVIDENCE_SCHEMA_VERSION,
    }
    assert {schema.version for schema in PAYLOAD_TYPES if schema.name == "claim_recorded"} == {
        SCHEMA_VERSION,
        CLAIM_SCHEMA_VERSION,
    }
    assert {schema.version for schema in PAYLOAD_TYPES if schema.name == "check_recorded"} == {
        SCHEMA_VERSION,
        "1.1.0",
        "1.2.0",
        "1.3.0",
        "1.4.0",
        "1.5.0",  # n6 item 4: deferred_before_first_edit
        "1.6.0",  # #1118: the reviewer record
    }
    assert {schema.version for schema in PAYLOAD_TYPES if schema.name == "finding_recorded"} == {
        SCHEMA_VERSION,
        "1.1.0",
        "1.2.0",
        "1.3.0",
        "1.4.0",
    }
    assert {
        schema.version for schema in PAYLOAD_TYPES if schema.name == "coordination_context_recorded"
    } == {"1.0.0"}
    assert {
        schema.version
        for schema in PAYLOAD_TYPES
        if schema.name == "coordination_disposition_recorded"
    } == {"1.0.0"}
    assert {
        schema.version
        for schema in PAYLOAD_TYPES
        if schema.name == "coordination_obligation_declared"
    } == {"1.0.0"}
    for family in ("session_opened", "session_resumed"):
        # session_opened 1.2.0 carries lineage and, optionally, the task statement; the
        # session_resumed 1.2.0 version exists only to carry the statement (issue #908).
        expected_versions = {SCHEMA_VERSION, "1.1.0", "1.2.0"}
        assert {
            schema.version for schema in PAYLOAD_TYPES if schema.name == family
        } == expected_versions
    for family in ("plan_published", "plan_revised", "obligation_published", "decision_recorded"):
        assert {schema.version for schema in PAYLOAD_TYPES if schema.name == family} == {
            SCHEMA_VERSION,
            "1.1.0",
        }
    assert all(
        schema.version == SCHEMA_VERSION
        for schema in PAYLOAD_TYPES
        if schema.name
        not in {
            "check_recorded",
            "claim_recorded",
            "decision_recorded",
            "evidence_recorded",
            "finding_recorded",
            "obligation_published",
            "plan_published",
            "plan_revised",
            "response_recorded",
            "result_recorded",
            "session_opened",
            "session_resumed",
        }
    )
    # Issue #1170: 1.1.0 adds only the optional agent-declared test manifest.
    assert {schema.version for schema in PAYLOAD_TYPES if schema.name == "result_recorded"} == {
        SCHEMA_VERSION,
        "1.1.0",
    }
    # Issue #997: 1.1.0 admits the obligation-level ``acknowledged_not_done`` status.
    assert {
        schema.version for schema in PAYLOAD_TYPES if schema.name == "obligation_published"
    } == {SCHEMA_VERSION, "1.1.0"}
    # Issue #905: 1.1.0 exists only for the terminal ``acknowledged_not_done`` disposition.
    assert {schema.version for schema in PAYLOAD_TYPES if schema.name == "response_recorded"} == {
        SCHEMA_VERSION,
        "1.1.0",
    }


def test_coordination_payloads_round_trip_with_closed_wire_shapes() -> None:
    context_schema = EventSchema("coordination_context_recorded", "1.0.0")
    context = decode_payload(context_schema, freeze_json(_coordination_context_wire()))
    assert type(context) is CoordinationContextRecordedPayload
    assert context.overlap_kind is OverlapKind.INTEGRATION
    assert context.source_task_id == context.counterpart_task_id
    assert encode_payload(context) == freeze_json(_coordination_context_wire())
    assert decode_payload(context_schema, encode_payload(context)) == context

    disposition_schema = EventSchema("coordination_disposition_recorded", "1.0.0")
    disposition = decode_payload(disposition_schema, freeze_json(_coordination_disposition_wire()))
    assert type(disposition) is CoordinationDispositionRecordedPayload
    assert disposition.disposition is CoordinationDisposition.SHARED_WORK
    assert encode_payload(disposition) == freeze_json(_coordination_disposition_wire())
    assert decode_payload(disposition_schema, encode_payload(disposition)) == disposition

    declaration_schema = EventSchema("coordination_obligation_declared", "1.0.0")
    declaration = decode_payload(
        declaration_schema,
        freeze_json(_coordination_obligation_declared_wire()),
    )
    assert type(declaration) is CoordinationObligationDeclaredPayload
    assert declaration.membership_generation == 3
    assert encode_payload(declaration) == freeze_json(_coordination_obligation_declared_wire())
    assert decode_payload(declaration_schema, encode_payload(declaration)) == declaration
    validate_schema_instance(
        "coordination-obligation-declared",
        "1.0.0",
        encode_payload(declaration),
    )


def test_coordination_payloads_reject_ambiguous_or_bare_wire_values() -> None:
    context_schema = EventSchema("coordination_context_recorded", "1.0.0")
    for field, value, reason in (
        (
            "source_task_id",
            "tsk_30000003-0000-4000-8000-000000000103",
            "coordination_task_pair_invalid",
        ),
        ("resource_count", "02", "invalid_event_value_type"),
    ):
        wire = _coordination_context_wire()
        wire[field] = value
        _assert_reason(reason, lambda wire=wire: decode_payload(context_schema, freeze_json(wire)))

    unsorted_resources = _coordination_context_wire()
    unsorted_resources["resource_identities"] = list(
        reversed(cast(list[str], unsorted_resources["resource_identities"]))
    )
    _assert_reason(
        "unsorted_set_field",
        lambda: decode_payload(context_schema, freeze_json(unsorted_resources)),
    )

    disposition_schema = EventSchema("coordination_disposition_recorded", "1.0.0")
    empty_evidence = _coordination_disposition_wire()
    empty_evidence["evidence_refs"] = []
    _assert_reason(
        "invalid_event_value_type",
        lambda: decode_payload(disposition_schema, freeze_json(empty_evidence)),
    )

    declaration_schema = EventSchema("coordination_obligation_declared", "1.0.0")
    declaration = _coordination_obligation_declared_wire()
    declaration["membership_generation"] = "03"
    _assert_reason(
        "invalid_event_value_type",
        lambda: decode_payload(declaration_schema, freeze_json(declaration)),
    )
    declaration = _coordination_obligation_declared_wire()
    declaration["unexpected"] = True
    _assert_reason(
        "unknown_payload_field",
        lambda: decode_payload(declaration_schema, freeze_json(declaration)),
    )
    row = _ROW_BY_FAMILY["session_opened"]
    valid_payload = freeze_json(row["payload"])
    for version in ("0.9.0", "1.0.1", "1.1.1", "2.0.0"):
        _assert_reason(
            "unknown_event_schema",
            lambda version=version: decode_payload(
                EventSchema("session_opened", version),
                valid_payload,
            ),
        )
    _assert_reason(
        "unknown_event_schema",
        lambda: decode_payload(EventSchema("future_family", "1.0.0"), valid_payload),
    )
    malformed = deepcopy(cast(dict[str, Any], row["payload"]))
    malformed["unexpected"] = True
    _assert_reason(
        "unknown_payload_field",
        lambda: decode_payload(_schema_for(row), freeze_json(malformed)),
    )


def test_claim_1_1_round_trip_keeps_revision_and_limitations_separate() -> None:
    payload = ClaimRecordedPayloadV1_1(
        claim_id=claim_id("clm_00000000-0000-4000-8000-000000000002"),
        claim_kind=ClaimKind.COMPLETION,
        statement="Narrowed completion with a disclosed partial result",
        supporting_refs=(evidence_id("evd_00000000-0000-4000-8000-000000000001"),),
        obligation_refs=(obligation_id("obl_00000000-0000-4000-8000-000000000001"),),
        limitation_refs=(result_id("res_00000000-0000-4000-8000-000000000001"),),
        supersedes_claim_refs=(claim_id("clm_00000000-0000-4000-8000-000000000001"),),
    )
    encoded_json = encode_payload(payload)
    encoded = cast(dict[str, Any], encoded_json)
    assert encoded["limitation_refs"] == ("res_00000000-0000-4000-8000-000000000001",)
    assert encoded["supersedes_claim_refs"] == ("clm_00000000-0000-4000-8000-000000000001",)
    assert (
        decode_payload(EventSchema("claim_recorded", CLAIM_SCHEMA_VERSION), encoded_json) == payload
    )
    _assert_reason(
        "unknown_payload_field",
        lambda: decode_payload(EventSchema("claim_recorded", SCHEMA_VERSION), encoded_json),
    )

    missing_limitations = dict(encoded)
    missing_limitations.pop("limitation_refs")
    _assert_reason(
        "missing_payload_field",
        lambda: decode_payload(
            EventSchema("claim_recorded", CLAIM_SCHEMA_VERSION), freeze_json(missing_limitations)
        ),
    )

    overlapping = dict(encoded)
    overlapping["supporting_refs"] = overlapping["limitation_refs"]
    _assert_reason(
        "claim_revision_invalid",
        lambda: decode_payload(
            EventSchema("claim_recorded", CLAIM_SCHEMA_VERSION), freeze_json(overlapping)
        ),
    )


def test_evidence_1_2_requires_closed_compatible_digest_provenance() -> None:
    legacy_row = _ROW_BY_FAMILY["evidence_recorded"]
    legacy_payload = cast(dict[str, Any], legacy_row["payload"])
    assert encode_payload(decode_payload(_schema_for(legacy_row), freeze_json(legacy_payload))) == (
        freeze_json(legacy_payload)
    )

    versioned = deepcopy(legacy_payload)
    versioned["strength"] = "content_digest"
    versioned.pop("captured_object_id", None)
    _assert_reason(
        "evidence_digest_binding_required",
        lambda: decode_payload(
            EventSchema("evidence_recorded", EVIDENCE_SCHEMA_VERSION),
            freeze_json(versioned),
        ),
    )
    versioned["digest_binding"] = {
        "subject": "source_diff",
        "content_availability": "digest_only",
        "byte_count": 128,
        "provenance": "caller_asserted",
    }
    _assert_reason(
        "evidence_digest_subject_incompatible",
        lambda: decode_payload(
            EventSchema("evidence_recorded", EVIDENCE_SCHEMA_VERSION),
            freeze_json(versioned),
        ),
    )
    versioned["evidence_kind"] = "artifact"
    decoded = cast(
        EvidenceRecordedPayload,
        decode_payload(
            EventSchema("evidence_recorded", EVIDENCE_SCHEMA_VERSION),
            freeze_json(versioned),
        ),
    )
    assert decoded.digest_binding == EvidenceDigestBinding(
        subject=EvidenceDigestSubject.SOURCE_DIFF,
        content_availability=EvidenceContentAvailability.DIGEST_ONLY,
        byte_count=128,
        provenance=EvidenceDigestProvenance.CALLER_ASSERTED,
    )
    validate_schema_instance(
        "event-draft",
        SCHEMA_VERSION,
        cast(
            CanonicalJsonValue,
            {
                "event_id": "evt_00000000-0000-4000-8000-000000000099",
                "schema": {
                    "name": "evidence_recorded",
                    "version": EVIDENCE_SCHEMA_VERSION,
                },
                "occurred_at": "2026-08-09T00:00:00.000Z",
                "causal_parents": [],
                "payload": versioned,
                "artifact_refs": [],
                "evidence_refs": [],
            },
        ),
    )

    captured = deepcopy(versioned)
    captured["strength"] = "immutable_snapshot"
    captured["captured_object_id"] = "obj_00000000-0000-4000-8000-000000000302"
    captured["digest_binding"] = {
        "subject": "bounded_excerpt",
        "content_availability": "captured",
        "byte_count": 128,
        "provenance": "observation_captured",
    }
    decoded_captured = cast(
        EvidenceRecordedPayload,
        decode_payload(
            EventSchema("evidence_recorded", EVIDENCE_SCHEMA_VERSION),
            freeze_json(captured),
        ),
    )
    assert decoded_captured.digest_binding is not None
    assert (
        decoded_captured.digest_binding.provenance is EvidenceDigestProvenance.OBSERVATION_CAPTURED
    )
    _assert_reason(
        "evidence_digest_provenance_invalid",
        lambda: decode_payload(EventSchema("evidence_recorded", "1.1.0"), freeze_json(captured)),
    )


def test_support_types_and_client_enum_identity_are_exact() -> None:
    from finishup.protocol import models

    assert ClientKind is models.ClientKind
    assert IntegrationKind is models.IntegrationKind
    assert tuple(member.value for member in RuntimeProfile) == (
        "strict-local",
        "local-openai",
        "codex-subscription",
        "test-fake",
        "release-probe",
    )
    assert tuple(member.value for member in RequestedItemKind) == (
        "url",
        "file",
        "command",
        "change",
        "source",
        "directory",
    )
    expected_enum_values = {
        NoObligationsReason: (
            "no_material_change",
            "single_atomic_change",
            "exploratory_scope_unknown",
        ),
        ObligationStatus: ("open", "resolved", "acknowledged_not_done"),
        WritePolicy: ("read_only", "writes_allowed"),
        ActionKind: ("command", "edit", "research", "review", "other"),
        ResultOutcome: ("success", "failure", "partial", "unknown"),
        EvidenceKind: (
            "artifact",
            "command_output",
            "test_result",
            "research_source",
            "import_report",
            "other",
        ),
        ClaimKind: ("completion", "material"),
        RequestedItemRole: ("input", "output"),
        ObligationChangeKind: ("superseded", "waived", "carried"),
        RedactionMethod: ("logical_redaction", "object_deletion"),
        RedactionReasonCategory: ("secret", "privacy", "retention", "legal", "other"),
        CheckMode: ("deterministic_only", "semantic_if_configured", "semantic_required"),
        RedactionState: ("present", "logically_redacted", "key_unavailable", "erased_claimed"),
    }
    for enum_type, expected in expected_enum_values.items():
        assert tuple(member.value for member in enum_type) == expected
    assert tuple(field.name for field in fields(RequestedItem)) == ("item_kind", "value", "role")
    assert tuple(field.name for field in fields(ObligationChange)) == (
        "obligation_id",
        "change",
        "reason",
        "replacement_obligation_ids",
    )
    assert tuple(field.name for field in fields(PolicyVersion)) == (
        "policy_id",
        "policy_version",
    )
    assert tuple(field.name for field in fields(EventSchema)) == ("name", "version")
    assert tuple(field.name for field in fields(WriterChain)) == (
        "writer_id",
        "sequence",
        "previous_entry_digest",
    )
    assert tuple(field.name for field in fields(LedgerChain)) == (
        "ingestion_sequence",
        "previous_entry_digest",
        "accepted_at",
    )
    assert tuple(field.name for field in fields(PayloadRef)) == (
        "object_id",
        "media_type",
        "plaintext_size",
        "commitment",
        "encryption_format",
    )
    assert tuple(field.name for field in fields(ProjectionLocator)) == (
        "schema",
        "logical_key",
        "canonical_payload_digest",
        "redaction_target_event_ids",
        "redaction_target_object_ids",
    )
    assert media_type_for("session_opened") == "application/vnd.yoetz.session_opened+json"


def test_chain_ref_bounds_and_imported_reason_precedence_are_exact() -> None:
    valid_writer = writer_id("wri_00000000-0000-4000-8000-000000000001")
    accepted_at = timestamp_from_string("2026-07-18T00:00:00.000Z")
    valid_object = object_id("obj_00000000-0000-4000-8000-000000000001")

    assert WriterChain(valid_writer, 1, "genesis").sequence == 1
    assert LedgerChain(1, "genesis", accepted_at).ingestion_sequence == 1
    assert (
        PayloadRef(
            valid_object,
            media_type_for("session_opened"),
            4_194_304,
            _COMMITMENT,
        ).plaintext_size
        == 4_194_304
    )

    _assert_reason("id_wrong_length", lambda: WriterChain(cast(Any, "bad"), 1, "genesis"))
    _assert_reason("invalid_chain", lambda: WriterChain(valid_writer, 0, "genesis"))
    _assert_reason("invalid_digest", lambda: WriterChain(valid_writer, 2, "not-a-digest"))
    _assert_reason(
        "invalid_timestamp",
        lambda: LedgerChain(1, "genesis", cast(Any, "not-a-timestamp")),
    )
    _assert_reason("id_wrong_length", lambda: PayloadRef(cast(Any, "bad"), "bad", 0, "bad"))
    _assert_reason(
        "invalid_payload_ref",
        lambda: PayloadRef(valid_object, "bad", 0, _COMMITMENT),
    )
    _assert_reason(
        "invalid_commitment",
        lambda: PayloadRef(valid_object, media_type_for("session_opened"), 0, "bad"),
    )
    _assert_reason(
        "invalid_payload_ref",
        lambda: PayloadRef(
            valid_object,
            media_type_for("session_opened"),
            4_194_305,
            _COMMITMENT,
        ),
    )

    assignment_schema = EventSchema("assignment_recorded", SCHEMA_VERSION)
    _assert_reason(
        "invalid_digest",
        lambda: ProjectionLocator(assignment_schema, "bad", "not-a-digest"),
    )
    _assert_reason(
        "id_wrong_length",
        lambda: ProjectionLocator(assignment_schema, "bad", _DIGEST),
    )
    redaction_schema = EventSchema("redaction_recorded", SCHEMA_VERSION)
    _assert_reason(
        "id_wrong_length",
        lambda: ProjectionLocator(
            redaction_schema,
            None,
            _DIGEST,
            redaction_target_event_ids=cast(Any, ("bad",)),
        ),
    )


def test_session_opened_preserves_full_start_content_and_independent_history_refs() -> None:
    only_external = SessionOpenedPayload(
        task_title="t" * 8_192,
        client_kind=ClientKind.TEST_CLIENT,
        client_version="0.1.0",
        integration=IntegrationKind.LOCAL_CLI,
        profile=RuntimeProfile.TEST_FAKE,
        external_ref="e" * 8_192,
    )
    only_workspace = SessionOpenedPayload(
        task_title="t" * 8_192,
        client_kind=ClientKind.TEST_CLIENT,
        client_version="0.1.0",
        integration=IntegrationKind.LOCAL_CLI,
        profile=RuntimeProfile.TEST_FAKE,
        workspace_ref="w" * 8_192,
    )
    assert only_external.workspace_ref is None
    assert only_workspace.external_ref is None
    _assert_reason(
        "event_text_out_of_bounds",
        lambda: SessionOpenedPayload(
            task_title="t" * 8_192,
            client_kind=ClientKind.TEST_CLIENT,
            client_version="0.1.0",
            integration=IntegrationKind.LOCAL_CLI,
            profile=RuntimeProfile.TEST_FAKE,
            external_ref="e" * 8_193,
        ),
    )


def test_current_lineage_events_bind_project_membership_generation() -> None:
    project = "prj_30000003-0000-4000-8000-000000000012"
    session_schema = EventSchema("session_opened", "1.2.0")
    session = SessionOpenedPayload(
        task_title="cross-repository child",
        client_kind=ClientKind.TEST_CLIENT,
        client_version="0.1.0",
        integration=IntegrationKind.COOPERATIVE_MCP,
        profile=RuntimeProfile.TEST_FAKE,
        parent_task_id=task_id("tsk_30000003-0000-4000-8000-000000000001"),
        depth=1,
        origin=LineageOrigin.PARENT_MINTED,
        project_id=project,
        membership_generation=7,
    )
    session_wire = cast(dict[str, Any], encode_payload(session))
    assert session_wire["project_id"] == project
    assert session_wire["membership_generation"] == "7"
    assert decode_payload(session_schema, freeze_json(session_wire)) == session
    validate_schema_instance("session-opened", "1.2.0", session_wire)
    _assert_reason(
        "invalid_event_schema",
        lambda: decode_payload(EventSchema("session_opened", "1.1.0"), freeze_json(session_wire)),
    )
    _assert_reason(
        "session_lineage_fields_incomplete",
        lambda: SessionOpenedPayload(
            task_title="cross-repository child",
            client_kind=ClientKind.TEST_CLIENT,
            client_version="0.1.0",
            integration=IntegrationKind.COOPERATIVE_MCP,
            profile=RuntimeProfile.TEST_FAKE,
            project_id=project,
        ),
    )

    delegation_schema = EventSchema("delegation_declared", "1.0.0")
    delegation = DelegationDeclaredPayload(
        child_task_id=task_id("tsk_30000003-0000-4000-8000-000000000002"),
        handle_digest="sha256:" + "3" * 64,
        depth=1,
        project_id=project,
        membership_generation=7,
    )
    delegation_wire = cast(dict[str, Any], encode_payload(delegation))
    assert delegation_wire["project_id"] == project
    assert delegation_wire["membership_generation"] == "7"
    assert decode_payload(delegation_schema, freeze_json(delegation_wire)) == delegation
    validate_schema_instance("delegation-declared", "1.0.0", delegation_wire)
    _assert_reason(
        "invalid_event_value_type",
        lambda: DelegationDeclaredPayload(
            child_task_id=task_id("tsk_30000003-0000-4000-8000-000000000002"),
            handle_digest="sha256:" + "3" * 64,
            depth=1,
            project_id=project,
        ),
    )


def test_family_specific_payload_invariants_fail_closed() -> None:
    action = cast(ActionRecordedPayload, _decode_row(_ROW_BY_FAMILY["action_recorded"]))
    _assert_reason(
        "invalid_event_value_type",
        lambda: replace(action, action_kind=ActionKind.COMMAND, command=None),
    )
    evidence = cast(EvidenceRecordedPayload, _decode_row(_ROW_BY_FAMILY["evidence_recorded"]))
    _assert_reason(
        "evidence_strength_unsupported",
        lambda: replace(
            evidence,
            strength=EvidenceImmutability.IMMUTABLE_SNAPSHOT,
            captured_object_id=None,
        ),
    )
    response = cast(ResponseRecordedPayload, _decode_row(_ROW_BY_FAMILY["response_recorded"]))
    _assert_reason(
        "response_fields_invalid",
        lambda: replace(
            response,
            disposition=ResponseDisposition.WAIVED,
            reason="approved waiver",
            waiver_scope=None,
        ),
    )
    _assert_reason(
        "response_fields_invalid",
        lambda: replace(
            response,
            disposition=ResponseDisposition.PROVENANCE_DISPUTED,
            reason=None,
        ),
    )
    _assert_reason(
        "response_fields_invalid",
        lambda: replace(
            response,
            disposition=ResponseDisposition.PROVENANCE_DISPUTED,
            reason="The finding attributes a claim to the wrong author.",
            waiver_scope=WaiverScope.FINDING_ONLY,
        ),
    )
    disputed = replace(
        response,
        disposition=ResponseDisposition.PROVENANCE_DISPUTED,
        reason="The finding attributes a claim to the wrong author.",
    )
    assert disputed.waiver_scope is None
    assert disputed.waiver_expiry is None
    revised = cast(PlanRevisedPayload, _decode_row(_ROW_BY_FAMILY["plan_revised"]))
    change = ObligationChange(
        obligation_id=revised.obligation_changes[0].obligation_id,
        change=ObligationChangeKind.CARRIED,
    )
    _assert_reason(
        "obligation_change_invalid",
        lambda: replace(change, replacement_obligation_ids=(change.obligation_id,)),
    )


def test_conditionally_forbidden_empty_arrays_do_not_normalize_to_absence() -> None:
    obligation_row = _ROW_BY_FAMILY["obligation_published"]
    obligation_wire = deepcopy(cast(dict[str, Any], obligation_row["payload"]))
    obligation_wire["status"] = "open"
    obligation_wire["resolution_evidence_refs"] = []
    _assert_reason(
        "obligation_resolution_invalid",
        lambda: decode_payload(_schema_for(obligation_row), freeze_json(obligation_wire)),
    )

    revision_row = _ROW_BY_FAMILY["plan_revised"]
    revision_schema = _schema_for(revision_row)
    for change_kind in ("waived", "carried"):
        revision_wire = deepcopy(cast(dict[str, Any], revision_row["payload"]))
        changes = cast(list[dict[str, Any]], revision_wire["obligation_changes"])
        changes[0]["change"] = change_kind
        changes[0]["replacement_obligation_ids"] = []
        _assert_reason(
            "obligation_change_invalid",
            lambda revision_wire=revision_wire: decode_payload(
                revision_schema,
                freeze_json(revision_wire),
            ),
        )

    superseded_wire = deepcopy(cast(dict[str, Any], revision_row["payload"]))
    superseded_changes = cast(
        list[dict[str, Any]],
        superseded_wire["obligation_changes"],
    )
    superseded_changes[0]["change"] = "superseded"
    superseded_changes[0]["replacement_obligation_ids"] = []
    _assert_reason(
        "schema_instance_invalid",
        lambda: validate_schema_instance(
            "plan-revised",
            SCHEMA_VERSION,
            cast(CanonicalJsonValue, superseded_wire),
        ),
    )

    duplicate_wire = deepcopy(superseded_wire)
    duplicate_changes = cast(
        list[dict[str, Any]],
        duplicate_wire["obligation_changes"],
    )
    duplicate_changes[0].pop("replacement_obligation_ids")
    duplicate_changes.append({**duplicate_changes[0], "replacement_obligation_ids": []})
    _assert_reason(
        "duplicate_set_member",
        lambda: decode_payload(revision_schema, freeze_json(duplicate_wire)),
    )


def test_evidence_strength_substance_and_import_authority_are_exact() -> None:
    evidence_row = _ROW_BY_FAMILY["evidence_recorded"]
    schema = _schema_for(evidence_row)
    base = cast(EvidenceRecordedPayload, _decode_row(evidence_row))
    complete = replace(
        base,
        reference="artifact://captured",
        description="captured verification material",
        subject_state=SubjectStateRef(described_state="captured state"),
    )
    for strength in EvidenceImmutability:
        candidate = replace(complete, strength=strength)
        assert decode_payload(schema, encode_payload(candidate)) == candidate

    missing_cases = (
        (EvidenceImmutability.MUTABLE_REFERENCE, {"reference": None}),
        (
            EvidenceImmutability.METADATA_ONLY,
            {"reference": None, "description": None},
        ),
        (EvidenceImmutability.CONTENT_DIGEST, {"content_digest": None}),
        (EvidenceImmutability.IMMUTABLE_SNAPSHOT, {"captured_object_id": None}),
        (EvidenceImmutability.IMMUTABLE_SNAPSHOT, {"content_digest": None}),
        (EvidenceImmutability.INDEPENDENTLY_REPRODUCED, {"captured_object_id": None}),
        (EvidenceImmutability.INDEPENDENTLY_REPRODUCED, {"content_digest": None}),
        (EvidenceImmutability.INDEPENDENTLY_REPRODUCED, {"subject_state": None}),
    )
    for strength, missing in missing_cases:
        _assert_reason(
            "evidence_strength_unsupported",
            lambda strength=strength, missing=missing: cast(Any, replace)(
                complete,
                strength=strength,
                **missing,
            ),
        )

    import_row = deepcopy(evidence_row)
    import_payload = cast(dict[str, Any], import_row["payload"])
    import_payload["evidence_kind"] = "import_report"
    import_envelope = cast(dict[str, Any], import_row["envelope"])
    import_author = cast(dict[str, Any], import_envelope["author"])
    import_author["actor_type"] = "importer"
    import_envelope["publication_channel"] = "codex_jsonl_import"
    import_coverage = cast(dict[str, Any], import_envelope["coverage"])
    import_coverage["publication_channels"] = ["codex_jsonl_import"]
    import_row["canonical_payload_digest"] = canonical_digest(freeze_json(import_payload))
    import_preimage = deepcopy(import_envelope)
    import_preimage.pop("entry_digest")
    import_envelope["entry_digest"] = entry_digest(JsonObject(import_preimage))

    imported = _accepted_from_row(import_row)
    assert (
        cast(EvidenceRecordedPayload, imported.payload).evidence_kind is EvidenceKind.IMPORT_REPORT
    )
    _assert_reason(
        "import_report_invalid",
        lambda: replace(
            imported,
            author=replace(imported.author, actor_type=ActorType.LOGICAL_AGENT),
        ),
    )
    wrong_channel = PublicationChannel.COOPERATIVE_MCP
    _assert_reason(
        "import_report_invalid",
        lambda: replace(
            imported,
            publication_channel=wrong_channel,
            coverage=replace(
                imported.coverage,
                publication_channels=(wrong_channel,),
            ),
        ),
    )
    _assert_reason(
        "import_report_invalid",
        lambda: replace(
            cast(EvidenceRecordedPayload, imported.payload),
            strength=EvidenceImmutability.INDEPENDENTLY_REPRODUCED,
            subject_state=SubjectStateRef(described_state="reproduced"),
        ),
    )


def test_subject_state_and_reference_fields_remain_bounded() -> None:
    action = cast(ActionRecordedPayload, _decode_row(_ROW_BY_FAMILY["action_recorded"]))
    state = SubjectStateRef(described_state="😀" * 256)
    action_with_state = replace(action, subject_state=state)
    action_schema = _schema_for(_ROW_BY_FAMILY["action_recorded"])
    assert decode_payload(action_schema, encode_payload(action_with_state)) == action_with_state
    _assert_reason(
        "invalid_subject_state",
        lambda: SubjectStateRef(described_state="x" * 257),
    )

    claim = cast(ClaimRecordedPayload, _decode_row(_ROW_BY_FAMILY["claim_recorded"]))
    refs = cast(tuple[Any, ...], _fixture_ids("evd_", 64))
    bounded_claim = replace(claim, supporting_refs=refs)
    claim_schema = _schema_for(_ROW_BY_FAMILY["claim_recorded"])
    assert decode_payload(claim_schema, encode_payload(bounded_claim)) == bounded_claim
    _assert_reason(
        "invalid_event_value_type",
        lambda: replace(claim, supporting_refs=cast(tuple[Any, ...], _fixture_ids("evd_", 65))),
    )
    _assert_reason(
        "duplicate_set_member",
        lambda: replace(claim, supporting_refs=cast(tuple[Any, ...], (refs[0], refs[0]))),
    )
    _assert_reason(
        "unsorted_set_field",
        lambda: replace(claim, supporting_refs=cast(tuple[Any, ...], (refs[1], refs[0]))),
    )

    result = cast(ResultRecordedPayload, _decode_row(_ROW_BY_FAMILY["result_recorded"]))
    _assert_reason(
        "id_wrong_prefix",
        lambda: replace(
            result,
            evidence_refs=cast(tuple[Any, ...], _fixture_ids("res_", 1)),
        ),
    )


def test_check_payload_records_normalized_scope_and_policy_executions() -> None:
    payload = cast(CheckRecordedPayload, _decode_row(_ROW_BY_FAMILY["check_recorded"]))
    assert type(payload.scope) is CheckScopeModel
    assert payload.scope.claim_ids == ()
    assert payload.scope.obligation_ids == ()
    assert tuple(execution.policy_id for execution in payload.policy_executions) == tuple(
        policy.policy_id for policy in payload.policies
    )
    _assert_reason(
        "invalid_event_value_type",
        lambda: replace(payload, policies=()),
    )
    reversed_executions = tuple(reversed(payload.policy_executions))
    if len(reversed_executions) == 2:
        _assert_reason(
            "invalid_event_value_type",
            lambda: replace(payload, policy_executions=reversed_executions),
        )


def _policy_execution(
    policy_id_value: str,
    outcome: str,
    reason: str,
) -> CheckPolicyExecutionModel:
    return CheckPolicyExecutionModel.model_validate(
        {
            "policy_id": policy_id_value,
            "policy_version": "0.1.0",
            "outcome": outcome,
            "reason": reason,
        }
    )


def test_check_payload_covers_two_pack_order_scope_and_all_execution_pairs() -> None:
    payload = cast(CheckRecordedPayload, _decode_row(_ROW_BY_FAMILY["check_recorded"]))
    schema = _schema_for(_ROW_BY_FAMILY["check_recorded"])
    for outcome, reason in (
        ("run", "completed"),
        ("skipped", "material_unavailable"),
        ("skipped", "not_applicable"),
        ("skipped", "scope_excluded"),
        ("failed", "policy_failure"),
    ):
        execution = _policy_execution("work-integrity", outcome, reason)
        candidate = replace(payload, policy_executions=(execution,))
        assert decode_payload(schema, encode_payload(candidate)) == candidate

    research = PolicyVersion("research-evidence", "0.1.0")
    work = PolicyVersion("work-integrity", "0.1.0")
    executions = (
        _policy_execution("research-evidence", "run", "completed"),
        _policy_execution("work-integrity", "skipped", "not_applicable"),
    )
    two_pack = replace(payload, policies=(research, work), policy_executions=executions)
    assert decode_payload(schema, encode_payload(two_pack)) == two_pack
    _assert_reason(
        "invalid_event_value_type",
        lambda: replace(
            payload,
            policies=(work, research),
            policy_executions=tuple(reversed(executions)),
        ),
    )
    _assert_reason(
        "invalid_event_value_type",
        lambda: replace(two_pack, policy_executions=tuple(reversed(executions))),
    )
    _assert_reason(
        "invalid_event_value_type",
        lambda: replace(
            payload,
            policy_executions=(executions[0],),
        ),
    )
    _assert_reason(
        "invalid_event_value_type",
        lambda: replace(payload, policy_executions=()),
    )

    check_row = _ROW_BY_FAMILY["check_recorded"]
    duplicate_wire = deepcopy(cast(dict[str, Any], check_row["payload"]))
    duplicate_wire["scope"] = {
        "claim_ids": [
            "clm_00000001-0000-4000-8000-000000000001",
            "clm_00000001-0000-4000-8000-000000000001",
        ],
        "obligation_ids": [],
    }
    _assert_reason(
        "duplicate_set_member",
        lambda: decode_payload(schema, freeze_json(duplicate_wire)),
    )
    unsorted_wire = deepcopy(cast(dict[str, Any], check_row["payload"]))
    unsorted_wire["scope"] = {
        "claim_ids": [
            "clm_00000002-0000-4000-8000-000000000002",
            "clm_00000001-0000-4000-8000-000000000001",
        ],
        "obligation_ids": [],
    }
    _assert_reason(
        "unsorted_set_field",
        lambda: decode_payload(schema, freeze_json(unsorted_wire)),
    )
    malformed_wire = deepcopy(cast(dict[str, Any], check_row["payload"]))
    malformed_wire["scope"] = {"claim_ids": ["bad"], "obligation_ids": []}
    _assert_reason(
        "id_wrong_length",
        lambda: decode_payload(schema, freeze_json(malformed_wire)),
    )

    for outcome, reason in (
        ("run", "policy_failure"),
        ("skipped", "completed"),
        ("failed", "not_applicable"),
    ):
        illegal_wire = deepcopy(cast(dict[str, Any], check_row["payload"]))
        illegal_executions = cast(
            list[dict[str, Any]],
            illegal_wire["policy_executions"],
        )
        illegal_executions[0]["outcome"] = outcome
        illegal_executions[0]["reason"] = reason
        _assert_reason(
            "invalid_event_enum",
            lambda illegal_wire=illegal_wire: decode_payload(
                schema,
                freeze_json(illegal_wire),
            ),
        )


def _selected_final_provenance() -> SemanticProvenance:
    return SemanticProvenance(
        provider="openai",
        endpoint_profile_id="review.default",
        endpoint_profile_version="1.0.0",
        model="gpt-5.4",
        sdk_version="2.46.0",
        prompt_digest=_DIGEST,
        schema_digest=_DIGEST,
        policy_digest=_DIGEST,
        privacy_policy_digest=_DIGEST,
        sampling_params=SamplingParams(max_output_tokens=2_048),
        latency_ms=1,
        semantic_attempt_id="att_00000000-0000-4000-8000-000000000001",
        dispatch_kind=SemanticDispatchKind.EXTERNAL,
        privacy_receipt_id="egr_00000000-0000-4000-8000-000000000002",
        status=SemanticStatus.SUCCEEDED,
        reason=SemanticReason.SEMANTIC_COMPLETED,
        egress_authorization_id="aut_00000000-0000-4000-8000-000000000003",
        request_commitment=_COMMITMENT,
    )


def _external_runtime_evidence() -> RuntimeAttemptEvidence:
    return RuntimeAttemptEvidence(
        credential_authority="external_runtime_oauth",
        runtime_version="0.150.1",
        runtime_source_identity="openai-codex-npm-darwin-arm64-0.150.1",
        executable_sha256=_DIGEST,
        app_server_schema_sha256=_DIGEST,
        capability_cell_sha256=_DIGEST,
        capability_profile="codex-evaluator/0.150.1/v1",
        capability_evidence_expires_at="2026-11-30T00:00:00Z",
        launcher_sha256=_DIGEST,
        isolated_config_sha256=_DIGEST,
        disclosed_case_sha256=_DIGEST,
        instruction_sha256=_DIGEST,
        output_schema_sha256=_DIGEST,
        selection_sha256=_DIGEST,
        upstream_body_observability="unavailable",
        auth_mode="chatgpt",
        plan_type="plus",
        reasoning_effort="high",
        thread_id="thread-1",
        turn_id="turn-1",
        final_output_sha256=_DIGEST,
        case_disclosed=True,
        turn_acknowledged=True,
        process_cleanup="terminated",
    )


def test_subscription_profile_requires_append_only_session_event_version() -> None:
    payload = SessionOpenedPayload(
        task_title="subscription task",
        client_kind=ClientKind.CODEX_CLI,
        client_version="0.1.0",
        integration=IntegrationKind.COOPERATIVE_MCP,
        profile=RuntimeProfile.CODEX_SUBSCRIPTION,
    )
    wire = encode_payload(payload)

    with pytest.raises(ProtocolValueError, match="invalid_event_value_type"):
        decode_payload(EventSchema("session_opened", "1.0.0"), wire)
    assert decode_payload(EventSchema("session_opened", "1.1.0"), wire) == payload


def test_subscription_provenance_requires_append_only_check_event_version() -> None:
    payload = cast(CheckRecordedPayload, _decode_row(_ROW_BY_FAMILY["check_recorded"]))
    provenance = replace(
        _selected_final_provenance(),
        provider="openai-codex",
        endpoint_profile_id="codex-chatgpt-subscription",
        model="gpt-5.6-sol",
        sdk_version="codex-app-server-0.150.1",
        dispatch_kind=SemanticDispatchKind.EXTERNAL_RUNTIME_OAUTH,
        runtime_evidence=_external_runtime_evidence(),
    )
    semantic = replace(
        payload,
        mode=CheckMode.SEMANTIC_REQUIRED,
        semantic_status=SemanticStatus.SUCCEEDED,
        semantic_reason=SemanticReason.SEMANTIC_COMPLETED,
        semantic_provenance=provenance,
    )
    wire = encode_payload(semantic)

    with pytest.raises(ProtocolValueError, match="invalid_event_value_type"):
        decode_payload(EventSchema("check_recorded", "1.0.0"), wire)
    assert decode_payload(EventSchema("check_recorded", "1.1.0"), wire) == semantic


def test_plain_check_written_by_older_builds_replays_at_every_legacy_version() -> None:
    """A plain check row from a released ledger must decode after an upgrade.

    Builds before the review-output check shape wrote plain deterministic checks as 1.0.0 (and
    the semantic line as 1.1.0); the current writer mints 1.2.0. Every one of those stays
    readable, while 1.3.0, 1.4.0 and 1.5.0 stay reserved for the payloads that introduced them.
    """
    row = _ROW_BY_FAMILY["check_recorded"]
    assert _schema_for(row) == EventSchema("check_recorded", SCHEMA_VERSION)
    wire = freeze_json(row["payload"])
    plain = cast(CheckRecordedPayload, decode_payload(EventSchema("check_recorded", "1.0.0"), wire))
    assert plain.semantic_conclusion is None
    assert plain.review_summary is None
    assert plain.totals is None
    for version in ("1.0.0", "1.1.0", "1.2.0"):
        decoded = decode_payload(EventSchema("check_recorded", version), wire)
        assert decoded == plain
        assert encode_payload(decoded) == wire
    for version in ("1.3.0", "1.4.0", "1.5.0"):
        _assert_reason(
            "invalid_event_schema",
            lambda version=version: decode_payload(EventSchema("check_recorded", version), wire),
        )


def test_check_payload_provenance_matches_selected_final_outcome() -> None:
    payload = cast(CheckRecordedPayload, _decode_row(_ROW_BY_FAMILY["check_recorded"]))
    provenance = _selected_final_provenance()
    semantic = replace(
        payload,
        mode=CheckMode.SEMANTIC_REQUIRED,
        semantic_status=SemanticStatus.SUCCEEDED,
        semantic_reason=SemanticReason.SEMANTIC_COMPLETED,
        semantic_provenance=provenance,
    )
    schema = _schema_for(_ROW_BY_FAMILY["check_recorded"])
    assert decode_payload(schema, encode_payload(semantic)) == semantic

    earlier_attempt = replace(
        provenance,
        status=SemanticStatus.TIMEOUT,
        reason=SemanticReason.PROVIDER_TIMEOUT,
    )
    _assert_reason(
        "invalid_semantic_provenance",
        lambda: replace(semantic, semantic_provenance=earlier_attempt),
    )


@pytest.mark.parametrize("family", _FIXTURE_FAMILIES)
@example(text_value="x" * 8_192, integer_value=9_007_199_254_740_991)
@settings(max_examples=20)
@given(
    text_value=_GENERATED_TEXT,
    integer_value=st.integers(min_value=0, max_value=9_007_199_254_740_991),
)
def test_generated_domain_payload_encode_decode_is_byte_stable(
    family: str,
    text_value: str,
    integer_value: int,
) -> None:
    schema = _schema_for(_ROW_BY_FAMILY[family])
    payload = _generated_payload(family, text_value, integer_value)
    first = encode_payload(payload)
    second = encode_payload(decode_payload(schema, first))
    assert canonical_encode(first) == canonical_encode(second)


@pytest.mark.parametrize(
    ("hash_seed", "timezone_name", "locale_name"),
    tuple(
        product(
            ("0", "4294967295"),
            ("UTC", "Pacific/Honolulu"),
            ("C", "en_US.UTF-8"),
        )
    ),
)
def test_generated_payload_bytes_match_across_process_environments(
    hash_seed: str,
    timezone_name: str,
    locale_name: str,
    tmp_path: Path,
) -> None:
    generated = _fixed_generated_payloads()
    matrix = tuple(
        {
            "schema": {"name": schema.name, "version": schema.version},
            "payload": encode_payload(payload),
        }
        for schema, payload in generated
    )
    encoded_matrix = canonical_encode(cast(CanonicalJsonValue, matrix))
    expected = sha256(
        canonical_encode(
            cast(CanonicalJsonValue, tuple(encode_payload(item) for _, item in generated))
        )
    ).hexdigest()
    environment = os.environ.copy()
    environment.update(
        {
            "PYTHONHASHSEED": hash_seed,
            "TZ": timezone_name,
            "LC_ALL": locale_name,
        }
    )
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            _EVENT_MATRIX_SCRIPT,
            str(_SRC_ROOT),
            base64.b64encode(encoded_matrix).decode("ascii"),
        ],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        check=False,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    assert result.stdout == expected + "\n"


def _locator_for(row: Mapping[str, Any], payload: object) -> ProjectionLocator:
    envelope = cast(dict[str, Any], row["envelope"])
    schema = _schema_for(row)
    family = schema.name
    wire = cast(dict[str, Any], row["payload"])
    if family in {"plan_published", "plan_revised"}:
        logical_key: str | None = str(wire["plan_version"])
    elif family == "obligation_published":
        logical_key = cast(str, wire["obligation_id"])
    elif family in {"assignment_recorded", "decision_recorded", "check_recorded"}:
        logical_key = cast(str, envelope["event_id"])
    elif family == "action_recorded":
        logical_key = cast(str, wire["action_id"])
    elif family == "result_recorded":
        logical_key = cast(str, wire["result_id"])
    elif family == "evidence_recorded":
        logical_key = cast(str, wire["evidence_id"])
    elif family == "claim_recorded":
        logical_key = cast(str, wire["claim_id"])
    elif family in {"finding_recorded", "response_recorded"}:
        logical_key = cast(str, wire["finding_id"])
    else:
        logical_key = None
    if family == "redaction_recorded":
        event_targets = tuple(cast(list[str], wire["target_event_ids"]))
        object_targets = tuple(cast(list[str], wire["target_object_ids"]))
    else:
        event_targets = ()
        object_targets = ()
    del payload
    return ProjectionLocator(
        schema=schema,
        logical_key=logical_key,
        canonical_payload_digest=cast(str, row["canonical_payload_digest"]),
        redaction_target_event_ids=cast(tuple[Any, ...], event_targets),
        redaction_target_object_ids=cast(tuple[Any, ...], object_targets),
    )


def _accepted_from_row(row: Mapping[str, Any]) -> AcceptedEvent:
    envelope = cast(dict[str, Any], row["envelope"])
    author = cast(dict[str, Any], envelope["author"])
    writer = cast(dict[str, Any], envelope["writer"])
    ledger = cast(dict[str, Any], envelope["ledger"])
    payload_ref = cast(dict[str, Any], envelope["payload_ref"])
    payload = _decode_row(row)
    return AcceptedEvent(
        event_id=event_id(envelope["event_id"]),
        task_id=task_id(envelope["task_id"]),
        session_id=session_id(envelope["session_id"]),
        schema=_schema_for(row),
        author=Actor(
            actor_id(author["actor_id"]),
            ActorType(author["actor_type"]),
            AuthorshipAssurance(author["assurance"]),
        ),
        writer=WriterChain(
            writer_id(writer["writer_id"]),
            int(writer["sequence"]),
            cast(str, writer["previous_entry_digest"]),
        ),
        ledger=LedgerChain(
            int(ledger["ingestion_sequence"]),
            cast(str, ledger["previous_entry_digest"]),
            timestamp_from_string(ledger["accepted_at"]),
        ),
        operation_id=request_id(envelope["operation_id"]),
        occurred_at=timestamp_from_string(envelope["occurred_at"]),
        causal_parents=cast(tuple[Any, ...], tuple(cast(list[str], envelope["causal_parents"]))),
        publication_channel=PublicationChannel(envelope["publication_channel"]),
        coverage=coverage_from_json(cast(CanonicalJsonValue, envelope["coverage"])),
        payload_ref=PayloadRef(
            object_id(payload_ref["object_id"]),
            cast(str, payload_ref["media_type"]),
            cast(int, payload_ref["plaintext_size"]),
            cast(str, payload_ref["commitment"]),
        ),
        redaction=RedactionState(envelope["redaction"]),
        artifact_refs=cast(tuple[Any, ...], tuple(cast(list[str], envelope["artifact_refs"]))),
        evidence_refs=cast(tuple[Any, ...], tuple(cast(list[str], envelope["evidence_refs"]))),
        entry_digest=cast(str, envelope["entry_digest"]),
        payload=cast(Any, payload),
        projection_locator=_locator_for(row, payload),
    )


def _unknown_fixture_row() -> dict[str, Any]:
    path = _FIXTURE_PATH.with_name("unknown-schema.case.json")
    document = cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))
    raw_input = cast(dict[str, Any], document["input"])
    rows = cast(list[dict[str, Any]], raw_input["accepted_entries"])
    return deepcopy(rows[1])


def _unknown_from_row(row: Mapping[str, Any]) -> UnknownEvent:
    envelope = cast(dict[str, Any], row["envelope"])
    author = cast(dict[str, Any], envelope["author"])
    writer = cast(dict[str, Any], envelope["writer"])
    ledger = cast(dict[str, Any], envelope["ledger"])
    payload_ref = cast(dict[str, Any], envelope["payload_ref"])
    schema = _schema_for(row)
    digest = cast(str, row["canonical_payload_digest"])
    return UnknownEvent(
        event_id=event_id(envelope["event_id"]),
        task_id=task_id(envelope["task_id"]),
        session_id=session_id(envelope["session_id"]),
        schema=schema,
        author=Actor(
            actor_id(author["actor_id"]),
            ActorType(author["actor_type"]),
            AuthorshipAssurance(author["assurance"]),
        ),
        writer=WriterChain(
            writer_id(writer["writer_id"]),
            int(writer["sequence"]),
            cast(str, writer["previous_entry_digest"]),
        ),
        ledger=LedgerChain(
            int(ledger["ingestion_sequence"]),
            cast(str, ledger["previous_entry_digest"]),
            timestamp_from_string(ledger["accepted_at"]),
        ),
        operation_id=request_id(envelope["operation_id"]),
        occurred_at=timestamp_from_string(envelope["occurred_at"]),
        causal_parents=cast(tuple[Any, ...], tuple(cast(list[str], envelope["causal_parents"]))),
        publication_channel=PublicationChannel(envelope["publication_channel"]),
        coverage=coverage_from_json(cast(CanonicalJsonValue, envelope["coverage"])),
        payload_ref=PayloadRef(
            object_id(payload_ref["object_id"]),
            cast(str, payload_ref["media_type"]),
            cast(int, payload_ref["plaintext_size"]),
            cast(str, payload_ref["commitment"]),
        ),
        redaction=RedactionState(envelope["redaction"]),
        artifact_refs=cast(tuple[Any, ...], tuple(cast(list[str], envelope["artifact_refs"]))),
        evidence_refs=cast(tuple[Any, ...], tuple(cast(list[str], envelope["evidence_refs"]))),
        entry_digest=cast(str, envelope["entry_digest"]),
        payload=freeze_json(row["payload"]),
        projection_locator=ProjectionLocator(schema, None, digest),
        canonical_payload_digest=digest,
    )


@pytest.mark.parametrize("family", _FIXTURE_FAMILIES)
def test_accepted_record_views_are_exact(family: str) -> None:
    row = _ROW_BY_FAMILY[family]
    record = _accepted_from_row(row)
    full = accepted_record_to_json(record)
    preimage = accepted_record_digest_preimage(record)
    assert len(full) == 19
    assert len(preimage) == 18
    assert set(full) - set(preimage) == {"entry_digest"}
    assert JsonObject(cast(dict[str, Any], row["envelope"])) == full
    assert entry_digest(preimage) == record.entry_digest
    assert "payload" not in full
    assert "projection_locator" not in full


def test_projection_locator_is_bounded_and_nonplaintext() -> None:
    for row in _ROWS:
        record = _accepted_from_row(row)
        locator = record.projection_locator
        wire = cast(dict[str, Any], row["payload"])
        family = record.schema.name
        field_by_family = {
            "plan_published": "plan_version",
            "plan_revised": "plan_version",
            "obligation_published": "obligation_id",
            "action_recorded": "action_id",
            "result_recorded": "result_id",
            "evidence_recorded": "evidence_id",
            "claim_recorded": "claim_id",
            "finding_recorded": "finding_id",
            "response_recorded": "finding_id",
        }
        if family in {"assignment_recorded", "decision_recorded", "check_recorded"}:
            expected_key: str | None = record.event_id
        elif family in field_by_family:
            expected_key = str(wire[field_by_family[family]])
        else:
            expected_key = None
        assert locator.schema == record.schema
        assert locator.logical_key == expected_key
        assert record.payload is not None
        assert locator.canonical_payload_digest == canonical_digest(encode_payload(record.payload))
        if family == "redaction_recorded":
            assert locator.redaction_target_event_ids == tuple(wire["target_event_ids"])
            assert locator.redaction_target_object_ids == tuple(wire["target_object_ids"])
        else:
            assert locator.redaction_target_event_ids == ()
            assert locator.redaction_target_object_ids == ()
        assert not any(
            text in repr(locator)
            for text in ("Synthetic all-family replay", "Execute the synthetic verification")
        )
    session_schema = EventSchema("session_opened", "1.0.0")
    _assert_reason(
        "invalid_projection_locator",
        lambda: ProjectionLocator(session_schema, "/workspace/private", _DIGEST),
    )


def test_projection_locator_schema_digest_and_target_exclusivity_fail_closed() -> None:
    record = _accepted_from_row(_ROW_BY_FAMILY["session_opened"])
    wrong_schema = ProjectionLocator(
        EventSchema("session_resumed", SCHEMA_VERSION),
        None,
        record.projection_locator.canonical_payload_digest,
    )
    _assert_reason(
        "invalid_projection_locator",
        lambda: replace(record, projection_locator=wrong_schema),
    )
    wrong_digest = replace(record.projection_locator, canonical_payload_digest=_DIGEST)
    _assert_reason(
        "invalid_projection_locator",
        lambda: replace(record, projection_locator=wrong_digest),
    )

    target_event = event_id("evt_00000000-0000-4000-8000-000000000001")
    _assert_reason(
        "invalid_projection_locator",
        lambda: ProjectionLocator(
            record.schema,
            None,
            record.projection_locator.canonical_payload_digest,
            redaction_target_event_ids=(target_event,),
        ),
    )
    redaction_schema = EventSchema("redaction_recorded", SCHEMA_VERSION)
    _assert_reason(
        "invalid_projection_locator",
        lambda: ProjectionLocator(redaction_schema, None, _DIGEST),
    )

    redaction = _accepted_from_row(_ROW_BY_FAMILY["redaction_recorded"])
    wrong_targets = replace(
        redaction.projection_locator,
        redaction_target_event_ids=(target_event,),
        redaction_target_object_ids=(),
    )
    _assert_reason(
        "invalid_projection_locator",
        lambda: replace(redaction, projection_locator=wrong_targets),
    )


def test_projection_locator_uses_exact_schema_pair_dispatch() -> None:
    schema = EventSchema("assignment_recorded", "1.0.1")
    locator = ProjectionLocator(schema, None, _DIGEST)
    assert locator.logical_key is None
    _assert_reason(
        "invalid_projection_locator",
        lambda: ProjectionLocator(
            schema,
            "evt_00000000-0000-4000-8000-000000000001",
            _DIGEST,
        ),
    )


@pytest.mark.parametrize(
    "family",
    ("assignment_recorded", "decision_recorded", "check_recorded"),
)
@pytest.mark.parametrize("redaction", tuple(RedactionState))
def test_payload_unavailable_locator_retains_derivable_event_key(
    family: str,
    redaction: RedactionState,
) -> None:
    record = _accepted_from_row(_ROW_BY_FAMILY[family])
    wrong_locator = replace(
        record.projection_locator,
        logical_key=event_id("evt_00000000-0000-4000-8000-000000000099"),
    )
    _assert_reason(
        "invalid_projection_locator",
        lambda: replace(
            record,
            payload=None,
            redaction=redaction,
            projection_locator=wrong_locator,
        ),
    )


def test_object_redaction_envelope_mirrors_are_exact() -> None:
    evidence = _accepted_from_row(_ROW_BY_FAMILY["evidence_recorded"])
    redaction = _accepted_from_row(_ROW_BY_FAMILY["redaction_recorded"])
    receipt = _accepted_from_row(_ROW_BY_FAMILY["receipt_recorded"])
    _assert_reason(
        "ref_mirror_mismatch",
        lambda: replace(evidence, artifact_refs=()),
    )
    _assert_reason(
        "ref_mirror_mismatch",
        lambda: replace(redaction, artifact_refs=()),
    )
    _assert_reason(
        "ref_mirror_mismatch",
        lambda: replace(receipt, artifact_refs=()),
    )


def test_envelope_evidence_refs_preserve_evidence_and_result_ids() -> None:
    response = cast(ResponseRecordedPayload, _decode_row(_ROW_BY_FAMILY["response_recorded"]))
    evidence_ref = cast(Any, "evd_00000000-0000-4000-8000-000000000001")
    result_ref = cast(Any, "res_00000000-0000-4000-8000-000000000002")
    response = replace(response, evidence_refs=(evidence_ref, result_ref))
    row = _ROW_BY_FAMILY["response_recorded"]
    envelope = cast(dict[str, Any], row["envelope"])
    draft = EventDraft(
        event_id=event_id(envelope["event_id"]),
        schema=_schema_for(row),
        occurred_at=timestamp_from_string(envelope["occurred_at"]),
        causal_parents=(),
        payload=response,
        artifact_refs=(),
        evidence_refs=(evidence_ref, result_ref),
    )
    assert draft.evidence_refs == response.evidence_refs
    _assert_reason(
        "ref_mirror_mismatch",
        lambda: replace(draft, evidence_refs=(evidence_ref,)),
    )

    result = cast(ResultRecordedPayload, _decode_row(_ROW_BY_FAMILY["result_recorded"]))
    result = replace(result, evidence_refs=(evidence_ref,))
    result_row = _ROW_BY_FAMILY["result_recorded"]
    result_envelope = cast(dict[str, Any], result_row["envelope"])
    result_draft = EventDraft(
        event_id=event_id(result_envelope["event_id"]),
        schema=_schema_for(result_row),
        occurred_at=timestamp_from_string(result_envelope["occurred_at"]),
        causal_parents=(),
        payload=result,
        artifact_refs=(),
        evidence_refs=(evidence_ref,),
    )
    assert result_draft.evidence_refs == result.evidence_refs
    _assert_reason(
        "ref_mirror_mismatch",
        lambda: replace(result_draft, evidence_refs=()),
    )


def test_unknown_event_is_preserved_opaque_and_unprojected() -> None:
    row = _unknown_fixture_row()
    record = _unknown_from_row(row)
    assert record.projection_status == "unknown_unprojected"
    assert record.projection_locator.logical_key is None
    assert (
        canonical_digest(cast(CanonicalJsonValue, record.payload))
        == record.canonical_payload_digest
    )
    assert accepted_record_to_json(record) == JsonObject(cast(dict[str, Any], row["envelope"]))
    _assert_reason(
        "invalid_event_schema",
        lambda: replace(
            record,
            schema=EventSchema("session_opened", "1.0.0"),
            payload_ref=replace(
                record.payload_ref,
                media_type=media_type_for("session_opened"),
            ),
        ),
    )

    known_name_row = deepcopy(row)
    known_payload = deepcopy(cast(dict[str, Any], _ROW_BY_FAMILY["session_opened"]["payload"]))
    known_envelope = cast(dict[str, Any], known_name_row["envelope"])
    known_schema = cast(dict[str, Any], known_envelope["schema"])
    known_schema["name"] = "session_opened"
    known_schema["version"] = "1.0.1"
    known_name_row["payload"] = known_payload
    known_name_row["canonical_payload_digest"] = canonical_digest(freeze_json(known_payload))
    known_payload_ref = cast(dict[str, Any], known_envelope["payload_ref"])
    known_payload_ref["media_type"] = media_type_for("session_opened")
    known_preimage = deepcopy(known_envelope)
    known_preimage.pop("entry_digest")
    known_envelope["entry_digest"] = entry_digest(JsonObject(known_preimage))

    version_unknown = _unknown_from_row(known_name_row)
    assert version_unknown.schema == EventSchema("session_opened", "1.0.1")
    assert version_unknown.projection_locator.logical_key is None
    assert version_unknown.projection_status == "unknown_unprojected"
    assert accepted_record_to_json(version_unknown) == JsonObject(known_envelope)


def test_record_integrity_and_redaction_mismatches_fail_before_replay() -> None:
    record = _accepted_from_row(_ROW_BY_FAMILY["session_opened"])
    _assert_reason(
        "entry_digest_mismatch",
        lambda: replace(record, entry_digest=_DIGEST),
    )
    _assert_reason(
        "payload_redaction_mismatch",
        lambda: replace(record, redaction=RedactionState.LOGICALLY_REDACTED),
    )


def test_finding_payload_is_the_exact_finding_alias() -> None:
    payload = _decode_row(_ROW_BY_FAMILY["finding_recorded"])
    assert FindingRecordedPayload is Finding
    assert type(payload) is Finding


def test_runtime_evidence_failure_stage_round_trips_and_stays_closed() -> None:
    from finishup.domain.findings import (
        RUNTIME_FAILURE_STAGES,
        semantic_provenance_from_json,
        semantic_provenance_to_json,
    )

    provenance = replace(
        _selected_final_provenance(),
        provider="openai-codex",
        endpoint_profile_id="codex-chatgpt-subscription",
        model="gpt-5.6-sol",
        sdk_version="codex-app-server-0.150.1",
        dispatch_kind=SemanticDispatchKind.EXTERNAL_RUNTIME_OAUTH,
        status=SemanticStatus.INVALID,
        reason=SemanticReason.RESPONSE_SCHEMA_INVALID,
        runtime_evidence=replace(
            _external_runtime_evidence(), failure_stage="judgment_refs_duplicate"
        ),
    )

    wire = semantic_provenance_to_json(provenance)
    evidence_json = cast(Mapping[str, object], wire["runtime_evidence"])
    assert evidence_json["failure_stage"] == "judgment_refs_duplicate"
    assert semantic_provenance_from_json(wire) == provenance

    success = semantic_provenance_to_json(_selected_final_provenance())
    assert "runtime_evidence" not in success

    for stage in RUNTIME_FAILURE_STAGES:
        replace(_external_runtime_evidence(), failure_stage=stage)
    with pytest.raises(ProtocolValueError, match="invalid_runtime_attempt_evidence"):
        replace(_external_runtime_evidence(), failure_stage="provider text must not land here")


def test_current_runtime_evidence_schema_accepts_every_failure_stage() -> None:
    """The current evidence schema must admit ``token_usage_invalid`` on a successful result.

    The stage is a nonterminal telemetry diagnostic, so a valid judgment carrying it has to pass
    every current result schema; a stale enum would make that result undeliverable on the wire.
    """

    from finishup.domain.findings import (
        RUNTIME_FAILURE_STAGES,
        semantic_provenance_to_json,
    )

    schema_path = (
        Path(__file__).resolve().parents[3]
        / "schemas/findings/runtime-attempt-evidence-1.1.0.schema.json"
    )
    document = json.loads(schema_path.read_text("utf-8"))
    assert set(document["properties"]["failure_stage"]["enum"]) == RUNTIME_FAILURE_STAGES

    provenance = replace(
        _selected_final_provenance(),
        provider="openai-codex",
        endpoint_profile_id="codex-chatgpt-subscription",
        model="gpt-5.6-luna",
        sdk_version="codex-app-server-0.150.1",
        dispatch_kind=SemanticDispatchKind.EXTERNAL_RUNTIME_OAUTH,
        runtime_evidence=replace(_external_runtime_evidence(), failure_stage="token_usage_invalid"),
    )
    wire = semantic_provenance_to_json(provenance)
    validate_schema_instance("semantic-provenance", "1.2.0", wire)
    payload = cast(CheckRecordedPayload, _decode_row(_ROW_BY_FAMILY["check_recorded"]))
    semantic = replace(
        payload,
        mode=CheckMode.SEMANTIC_REQUIRED,
        semantic_status=SemanticStatus.SUCCEEDED,
        semantic_reason=SemanticReason.SEMANTIC_COMPLETED,
        semantic_provenance=provenance,
    )
    validate_schema_instance("check-recorded", "1.2.0", encode_payload(semantic))


def test_runtime_evidence_token_usage_is_additive_and_omits_absent_bytes() -> None:
    from finishup.domain.findings import semantic_provenance_from_json, semantic_provenance_to_json

    base = replace(
        _selected_final_provenance(),
        provider="openai-codex",
        endpoint_profile_id="codex-chatgpt-subscription",
        model="gpt-5.6-luna",
        sdk_version="codex-app-server-0.150.1",
        dispatch_kind=SemanticDispatchKind.EXTERNAL_RUNTIME_OAUTH,
        runtime_evidence=_external_runtime_evidence(),
    )
    runtime_evidence = base.runtime_evidence
    assert runtime_evidence is not None
    without_usage = base
    without_usage_wire = semantic_provenance_to_json(without_usage)
    without_usage_runtime = cast(Mapping[str, object], without_usage_wire["runtime_evidence"])
    assert "token_usage" not in without_usage_runtime

    usage = RuntimeTokenUsage(
        input_tokens=160,
        cached_input_tokens=80,
        cache_write_input_tokens=5,
        output_tokens=50,
        reasoning_output_tokens=20,
        total_tokens=210,
    )
    with_usage = replace(
        without_usage,
        runtime_evidence=replace(runtime_evidence, token_usage=usage),
    )
    wire = semantic_provenance_to_json(with_usage)
    runtime = cast(Mapping[str, object], wire["runtime_evidence"])
    usage_wire = cast(Mapping[str, object], runtime["token_usage"])
    assert usage_wire == {
        "cached_input_tokens": "80",
        "cache_write_input_tokens": "5",
        "input_tokens": "160",
        "output_tokens": "50",
        "reasoning_output_tokens": "20",
        "total_tokens": "210",
    }
    assert semantic_provenance_from_json(wire) == with_usage
    validate_schema_instance("semantic-provenance", "1.2.0", wire)

    with pytest.raises(ProtocolValueError, match="schema_instance_invalid"):
        validate_schema_instance("semantic-provenance", "1.1.0", wire)

    payload = cast(CheckRecordedPayload, _decode_row(_ROW_BY_FAMILY["check_recorded"]))
    semantic = replace(
        payload,
        mode=CheckMode.SEMANTIC_REQUIRED,
        semantic_status=SemanticStatus.SUCCEEDED,
        semantic_reason=SemanticReason.SEMANTIC_COMPLETED,
        semantic_provenance=with_usage,
    )
    event_wire = encode_payload(semantic)
    assert decode_payload(EventSchema("check_recorded", "1.2.0"), event_wire) == semantic
    with pytest.raises(ProtocolValueError, match="schema_instance_invalid"):
        validate_schema_instance("check-recorded", "1.1.0", event_wire)
