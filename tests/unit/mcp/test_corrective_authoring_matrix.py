"""A rejected request must be repairable from the public output alone, on the next call.

The 2026-08-03 `codex-testing` dogfood rejected 9 of 17 FinishUP operations. Validation was
fail-closed and safe throughout, but three failure classes did not say how to author the next
request, so the agent guessed four times and then read FinishUP product source -- the one thing the
packaged workflow forbids.

Every row here replays one of those classes and asserts two things: the public output names every
field the repair needs, and the request repaired from that output alone is admitted by the real
models. Asserting only the message text would pass on prose that says the wrong thing.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Final, cast

import pytest
from pydantic import ValidationError

from builders.replay import replay_records
from finishup.application.publish_work import Application, prepare_publication
from finishup.domain.events import EventPayload, encode_payload
from finishup.mcp.descriptors import descriptor_for
from finishup.mcp.errors import safe_validation_locations
from finishup.mcp.server import invalid_request_message
from finishup.protocol.canonical import JsonValue
from finishup.protocol.coverage import PublicationChannel
from finishup.protocol.errors import PublicErrorCode, PublicOperationError
from finishup.protocol.models import CheckRequestModel, PublishWorkRequestModel

type _Request = dict[str, JsonValue]

_CHECK_EXAMPLE: Final = cast(
    Mapping[str, JsonValue],
    cast(list[JsonValue], descriptor_for("check").input_schema["examples"])[0],
)
_PUBLISH_EXAMPLE: Final = cast(
    Mapping[str, JsonValue],
    cast(list[JsonValue], descriptor_for("publish_work").input_schema["examples"])[0],
)


def _publish_request(drafts: list[JsonValue]) -> _Request:
    return {**dict(_PUBLISH_EXAMPLE), "event_drafts": drafts}


def _example_draft() -> _Request:
    drafts = cast(list[JsonValue], _PUBLISH_EXAMPLE["event_drafts"])
    return dict(cast(Mapping[str, JsonValue], drafts[0]))


def _guessed_discriminator() -> _Request:
    """The dogfood's own mistake: the family value on a guessed top-level key."""

    draft = _example_draft()
    schema = cast(Mapping[str, JsonValue], draft.pop("schema"))
    draft["event_type"] = schema["name"]
    return _publish_request([draft])


def _repair_discriminator(rejected: _Request) -> _Request:
    drafts = cast(list[JsonValue], rejected["event_drafts"])
    draft = dict(cast(Mapping[str, JsonValue], drafts[0]))
    family = draft.pop("event_type")
    draft["schema"] = {"name": family, "version": "1.0.0"}
    return _publish_request([draft])


def _missing_envelope_keys() -> _Request:
    draft = _example_draft()
    draft.pop("artifact_refs", None)
    draft.pop("evidence_refs", None)
    return _publish_request([draft])


def test_omitted_fillable_envelope_keys_are_admitted() -> None:
    """Issue #1084: the service fills omitted envelope keys, so their absence is no rejection."""

    PublishWorkRequestModel.model_validate(_missing_envelope_keys())
    draft = _example_draft()
    assert set(draft) == {"schema", "payload"}
    PublishWorkRequestModel.model_validate(_publish_request([draft]))


def _stub_draft() -> _Request:
    return _publish_request(
        [{"event_id": "evt_00000000-0000-4000-8000-000000000001", "payload": {}}]
    )


def _repair_stub_draft(rejected: _Request) -> _Request:
    del rejected
    return _publish_request([cast(JsonValue, _example_draft())])


def _empty_scope() -> _Request:
    return {**dict(_CHECK_EXAMPLE), "scope": {}}


def _half_scope() -> _Request:
    return {**dict(_CHECK_EXAMPLE), "scope": {"obligation_ids": []}}


def _repair_scope_by_completing_it(rejected: _Request) -> _Request:
    del rejected
    return {**dict(_CHECK_EXAMPLE), "scope": {"claim_ids": [], "obligation_ids": []}}


def _repair_scope_by_omitting_it(rejected: _Request) -> _Request:
    del rejected
    return dict(_CHECK_EXAMPLE)


# tool, label, rejected request, field names the repair needs, repair derived from the output only.
_AUTHORING_MATRIX: Final[
    tuple[
        tuple[str, str, Callable[[], _Request], tuple[str, ...], Callable[[_Request], _Request]],
        ...,
    ]
] = (
    (
        "publish_work",
        "guessed top-level discriminator",
        _guessed_discriminator,
        ("schema.name", "plan_published"),
        _repair_discriminator,
    ),
    (
        "publish_work",
        "stub draft with only an id and a payload",
        _stub_draft,
        # Issue #1084: the service fills every other envelope key, so only the family is named.
        ("schema.name", "schema and payload"),
        _repair_stub_draft,
    ),
    (
        "check",
        "empty scope object",
        _empty_scope,
        ("scope", "claim_ids", "obligation_ids"),
        _repair_scope_by_completing_it,
    ),
    (
        "check",
        "scope with only obligation_ids",
        _half_scope,
        ("scope", "claim_ids", "obligation_ids"),
        _repair_scope_by_omitting_it,
    ),
)

_MODELS: Final = {
    "publish_work": PublishWorkRequestModel,
    "check": CheckRequestModel,
}


def _rejection_message(tool: str, request: _Request) -> str:
    model = _MODELS[tool]
    with pytest.raises(ValidationError) as captured:
        model.model_validate(request)
    return invalid_request_message(tool, safe_validation_locations(captured.value))


@pytest.mark.parametrize(
    ("tool", "label", "build", "needed_names", "repair"),
    _AUTHORING_MATRIX,
    ids=[row[1] for row in _AUTHORING_MATRIX],
)
def test_one_retry_repairs_the_request_from_the_public_output(
    tool: str,
    label: str,
    build: Callable[[], _Request],
    needed_names: tuple[str, ...],
    repair: Callable[[_Request], _Request],
) -> None:
    rejected = build()
    message = _rejection_message(tool, rejected)

    for name in needed_names:
        assert name in message, f"{label}: the output never names {name}"

    # The repaired request is derived from the rejected one plus the message, and must be admitted
    # by the real model. A message that names the fields but states the wrong rule fails here.
    _MODELS[tool].model_validate(repair(rejected))


def test_the_scope_rule_names_the_third_admitted_shape() -> None:
    """Naming the missing peer alone still hides that dropping scope is a repair."""

    message = _rejection_message("check", _empty_scope())
    assert "omit scope for the whole case" in message
    assert "two empty arrays also mean the whole case" in message


def test_the_draft_envelope_rule_names_where_the_family_goes() -> None:
    message = _rejection_message("publish_work", _guessed_discriminator())
    assert "each event_drafts entry requires" in message
    assert "schema.name admits" in message
    # The guessed keys the dogfood tried must never be reported back as if they were admitted.
    for guess in ("event_type", "event_family"):
        assert guess not in message


class _App:
    def authorizes_import_publication(self, request: PublishWorkRequestModel) -> bool:
        del request
        return False


def _record_draft(family: str) -> tuple[_Request, object]:
    record = next(row for row in replay_records("all-event-families") if row.schema.name == family)
    assert record.payload is not None
    draft: _Request = {
        "event_id": record.event_id,
        "schema": {"name": record.schema.name, "version": record.schema.version},
        "occurred_at": record.occurred_at.wire,
        "causal_parents": list(record.causal_parents),
        "payload": encode_payload(cast(EventPayload, record.payload)),
        "artifact_refs": list(record.artifact_refs),
        "evidence_refs": list(record.evidence_refs),
    }
    return draft, record


def _publish_model(drafts: list[JsonValue], record: object) -> PublishWorkRequestModel:
    return PublishWorkRequestModel.model_validate(
        {
            "protocol_version": "0.1",
            "schema_version": "1.0.0",
            "request_id": "req_00000000-0000-4000-8000-000000000401",
            "session_id": getattr(record, "session_id"),
            "writer_id": getattr(record, "writer").writer_id,
            "expected_frontier": {"sequence": "0", "head_digest": "genesis"},
            "event_drafts": tuple(drafts),
            "actor": {"actor_id": "harness:test", "actor_type": "harness"},
            "client": {"kind": "test_client", "version": "0.1.0", "integration": "local_cli"},
        }
    )


_MIRROR_MATRIX: Final = (
    ("result_recorded", "evidence_refs", "evd_00000000-0000-4000-8000-0000000000ff"),
    ("response_recorded", "evidence_refs", "evd_00000000-0000-4000-8000-0000000000ff"),
    ("evidence_recorded", "artifact_refs", "obj_00000000-0000-4000-8000-0000000000ff"),
    ("receipt_recorded", "artifact_refs", "obj_00000000-0000-4000-8000-0000000000ff"),
    ("redaction_recorded", "artifact_refs", "obj_00000000-0000-4000-8000-0000000000ff"),
)


@pytest.mark.parametrize(("family", "envelope_field", "intruder"), _MIRROR_MATRIX)
def test_a_broken_reference_mirror_names_the_field_and_the_rule(
    family: str, envelope_field: str, intruder: str
) -> None:
    """`ref_mirror_mismatch` reached the agent with no corrective text and a draft-level pointer."""

    filler, filler_record = _record_draft("action_recorded")
    broken, _ = _record_draft(family)
    mirrored = cast(list[JsonValue], broken[envelope_field])
    broken[envelope_field] = [] if mirrored else [intruder]

    with pytest.raises(PublicOperationError) as captured:
        prepare_publication(
            _publish_model([cast(JsonValue, filler), cast(JsonValue, broken)], filler_record),
            channel=PublicationChannel.LOCAL_CLI,
            app=cast(Application, _App()),
        )

    error = captured.value
    assert error.code is PublicErrorCode.EVENT_INVALID
    details = cast(Mapping[str, str], error.safe_details)
    assert details["reason_code"] == "ref_mirror_mismatch"
    # The pointer names the exact list to fix, not just which draft failed.
    assert details["field"] == f"/event_drafts/1/{envelope_field}"
    assert envelope_field in error.message
    assert "example:" in error.message
    assert "0000000000ff" not in error.message
    assert "finishup://guidance/publication-policy.md" in error.message
    assert error.message != "The event batch is invalid. Correct the event payload before retrying."


# Only the ordinary cooperative families can also be published; the reserved ones are rejected by
# admission after decoding, so the mirror repair is asserted on the families an agent can send.
_PUBLISHABLE_MIRROR_MATRIX: Final = tuple(
    row for row in _MIRROR_MATRIX if row[0] in {"result_recorded", "evidence_recorded"}
)


@pytest.mark.parametrize(("family", "envelope_field", "intruder"), _PUBLISHABLE_MIRROR_MATRIX)
def test_restoring_the_mirrored_field_is_admitted(
    family: str, envelope_field: str, intruder: str
) -> None:
    """The stated repair -- put the mirror back -- must actually be the one that is accepted."""

    del intruder
    filler, filler_record = _record_draft("action_recorded")
    repaired, _ = _record_draft(family)

    prepared = prepare_publication(
        _publish_model([cast(JsonValue, filler), cast(JsonValue, repaired)], filler_record),
        channel=PublicationChannel.LOCAL_CLI,
        app=cast(Application, _App()),
    )

    assert prepared.drafts[1].draft.schema.name == family
    assert envelope_field in {"artifact_refs", "evidence_refs"}


def test_no_submitted_value_reaches_a_reference_mirror_message() -> None:
    secret = "obj_00000000-0000-4000-8000-00000000dead"
    filler, filler_record = _record_draft("action_recorded")
    broken, _ = _record_draft("evidence_recorded")
    broken["artifact_refs"] = [secret]

    with pytest.raises(PublicOperationError) as captured:
        prepare_publication(
            _publish_model([cast(JsonValue, filler), cast(JsonValue, broken)], filler_record),
            channel=PublicationChannel.LOCAL_CLI,
            app=cast(Application, _App()),
        )

    assert secret not in captured.value.message
    assert secret not in repr(captured.value.safe_details)


def _obligation_with_commands(*values: str) -> tuple[_Request, object]:
    draft, record = _record_draft("obligation_published")
    payload = dict(cast(Mapping[str, JsonValue], draft["payload"]))
    payload["requested_items"] = [
        {"item_kind": "file", "value": "results.json"},
        *({"item_kind": "command", "value": value} for value in values),
    ]
    draft["payload"] = payload
    return draft, record


def test_a_placeholder_command_item_is_refused_with_its_exact_location_and_repair() -> None:
    """tb4n1: `python cracker.py <ciphertext_file>` could never match an observed run (#977)."""

    broken, record = _obligation_with_commands("pytest -q", "python cracker.py <ciphertext_file>")

    with pytest.raises(PublicOperationError) as captured:
        prepare_publication(
            _publish_model([cast(JsonValue, broken)], record),
            channel=PublicationChannel.LOCAL_CLI,
            app=cast(Application, _App()),
        )

    error = captured.value
    assert error.code is PublicErrorCode.EVENT_INVALID
    details = cast(Mapping[str, str], error.safe_details)
    assert details["reason_code"] == "requested_command_placeholder"
    assert details["field"] == "/event_drafts/0/payload/requested_items/2/value"
    assert "placeholder" in error.message and "acceptance_criteria" in error.message
    # The submitted value never reaches the public output.
    assert "ciphertext_file" not in error.message
    assert "ciphertext_file" not in repr(error.safe_details)


@pytest.mark.parametrize(
    "value", ["python cracker.py data/cipher.bin", "Broad GSEA CLI", "grep '<div>' index.html"]
)
def test_concrete_prose_or_quoted_angle_brackets_are_admitted(value: str) -> None:
    repaired, record = _obligation_with_commands(value)

    prepared = prepare_publication(
        _publish_model([cast(JsonValue, repaired)], record),
        channel=PublicationChannel.LOCAL_CLI,
        app=cast(Application, _App()),
    )

    assert prepared.drafts[0].draft.schema.name == "obligation_published"
