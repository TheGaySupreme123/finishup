"""Request-digest and accepted-record identity conformance."""

from __future__ import annotations

from copy import deepcopy
from typing import Any, cast

import pytest

from builders.replay import replay_records
from finishup.domain.events import (
    PayloadRef,
    accepted_record_digest_preimage,
    accepted_record_to_json,
)
from finishup.domain.values import object_id
from finishup.protocol.canonical import (
    JsonValue,
    canonical_encode,
    entry_digest,
    request_digest,
    strict_json_parse,
)
from finishup.protocol.errors import ProtocolValueError
from finishup.protocol.models import MAX_OBJECT_PLAINTEXT_BYTES
from finishup.protocol.schemas import validate_schema_instance
from fixture_loader import FixtureLoader


def _fixture(loader: FixtureLoader, path: str) -> dict[str, Any]:
    return cast(dict[str, Any], loader.load_json(path))


def _publication_vectors(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    fixture_input = cast(dict[str, Any], document["input"])
    variants = cast(list[dict[str, Any]], fixture_input["identity_variants"])
    return {cast(str, item["variant_id"]): item for item in variants}


def _expected_publication_digests(document: dict[str, Any]) -> dict[str, str]:
    expected = cast(dict[str, Any], document["expected"])
    assertions = cast(list[dict[str, Any]], expected["assertions"])
    return {cast(str, item["variant_id"]): cast(str, item["request_digest"]) for item in assertions}


def test_publish_work_request_digest_excludes_generated_fields(
    fixture_loader: FixtureLoader,
) -> None:
    document = _fixture(
        fixture_loader,
        "canonical/publication-request-identity.case.json",
    )
    variants = _publication_vectors(document)
    attempts = {
        cast(str, item["attempt_id"]): item
        for item in cast(
            list[dict[str, Any]], cast(dict[str, Any], document["input"])["publication_attempts"]
        )
    }

    first = cast(JsonValue, variants["first-publication"]["identity"])
    retry = cast(JsonValue, variants["logical-retry-fresh-encryption"]["identity"])
    assert first == retry
    assert request_digest(first) == request_digest(retry)
    assert (
        attempts["fresh-encryption-a"]["object_id"] != attempts["fresh-encryption-b"]["object_id"]
    )
    assert (
        attempts["fresh-encryption-a"]["payload_nonce_hex"]
        != attempts["fresh-encryption-b"]["payload_nonce_hex"]
    )
    assert (
        attempts["fresh-encryption-a"]["payload_commitment"]
        == attempts["fresh-encryption-b"]["payload_commitment"]
    )


def test_accepted_entry_digest_covers_structural_envelope(
    fixture_loader: FixtureLoader,
) -> None:
    document = _fixture(fixture_loader, "canonical/accepted-entry-identity.case.json")
    expected = cast(dict[str, Any], document["expected"])
    arrangements = cast(list[dict[str, Any]], expected["arrangements"])
    by_name = {cast(str, item["arrangement_id"]): item for item in arrangements}

    for arrangement in arrangements:
        for expected_entry in cast(list[dict[str, Any]], arrangement["entries"]):
            preimage = strict_json_parse(
                bytes.fromhex(cast(str, expected_entry["digest_preimage_hex"]))
            )
            assert entry_digest(preimage) == expected_entry["entry_digest"]

    single = cast(list[dict[str, Any]], by_name["single-writer-chain"]["entries"])
    split = cast(list[dict[str, Any]], by_name["split-writer-chains"]["entries"])
    assert single[0]["entry_digest"] == split[0]["entry_digest"]
    assert single[1]["entry_digest"] != split[1]["entry_digest"]


def test_accepted_record_and_digest_preimage_are_distinct_views() -> None:
    record = replay_records("all-event-families")[0]
    full = accepted_record_to_json(record)
    preimage = accepted_record_digest_preimage(record)

    assert tuple(full) == (*tuple(preimage), "entry_digest")
    assert full["entry_digest"] == record.entry_digest
    assert "entry_digest" not in preimage
    assert "payload" not in full
    assert "payload" not in preimage
    assert entry_digest(preimage) == record.entry_digest
    validate_schema_instance("accepted-event", "1.0.0", full)
    with pytest.raises(ProtocolValueError, match="schema_instance_invalid"):
        validate_schema_instance("accepted-event", "1.0.0", preimage)


@pytest.mark.parametrize(
    "mutation",
    (
        "embedded_digest",
        "decoded_payload",
        "missing_field",
        "extra_field",
        "wrong_protocol",
    ),
)
def test_entry_digest_rejects_non_preimage_views(mutation: str) -> None:
    preimage = cast(
        dict[str, Any],
        dict(accepted_record_digest_preimage(replay_records("all-event-families")[0])),
    )
    if mutation == "embedded_digest":
        preimage["entry_digest"] = "sha256:" + "0" * 64
    elif mutation == "decoded_payload":
        preimage["payload"] = {"invented": True}
    elif mutation == "missing_field":
        del preimage["artifact_refs"]
    elif mutation == "extra_field":
        preimage["transport"] = {}
    else:
        preimage["protocol"] = "finishup"

    with pytest.raises(ProtocolValueError) as caught:
        entry_digest(cast(JsonValue, preimage))
    assert caught.value.reason_code == "not_an_accepted_envelope"

    with pytest.raises(ProtocolValueError, match="not_an_accepted_envelope"):
        entry_digest(cast(Any, ()))


@pytest.mark.parametrize("size", (0, MAX_OBJECT_PLAINTEXT_BYTES))
def test_payload_ref_plaintext_size_is_bounded_json_integer(size: int) -> None:
    payload_ref = PayloadRef(
        object_id("obj_00000000-0000-4000-8000-000000000001"),
        "application/vnd.yoetz.plan_published+json",
        size,
        "hmac-sha256:" + "0" * 64,
    )
    assert payload_ref.plaintext_size == size

    full = cast(
        dict[str, Any],
        dict(accepted_record_to_json(replay_records("all-event-families")[0])),
    )
    nested = dict(cast(dict[str, JsonValue], full["payload_ref"]))
    nested["plaintext_size"] = size
    full["payload_ref"] = nested
    validate_schema_instance("accepted-event", "1.0.0", cast(JsonValue, full))


@pytest.mark.parametrize(
    "size",
    (-1, MAX_OBJECT_PLAINTEXT_BYTES + 1, True, "1", 1.5),
)
def test_payload_ref_plaintext_size_rejects_non_json_integers(size: object) -> None:
    with pytest.raises(ProtocolValueError, match="invalid_payload_ref"):
        PayloadRef(
            object_id("obj_00000000-0000-4000-8000-000000000001"),
            "application/vnd.yoetz.plan_published+json",
            cast(Any, size),
            "hmac-sha256:" + "0" * 64,
        )


def test_replayed_logical_identity_is_stable(fixture_loader: FixtureLoader) -> None:
    document = _fixture(
        fixture_loader,
        "canonical/publication-request-identity.case.json",
    )
    vectors = _publication_vectors(document)
    expected = _expected_publication_digests(document)
    for variant_id, vector in vectors.items():
        identity = cast(JsonValue, vector["identity"])
        assert canonical_encode(identity) == canonical_encode(deepcopy(identity))
        assert request_digest(identity) == expected[variant_id]


def test_idempotency_conflict_is_identity_conflict_not_payload_diff(
    fixture_loader: FixtureLoader,
) -> None:
    document = _fixture(
        fixture_loader,
        "canonical/publication-request-identity.case.json",
    )
    vectors = _publication_vectors(document)
    expected = _expected_publication_digests(document)
    first = vectors["first-publication"]
    changed = vectors["same-key-material-change-conflict"]

    first_identity = cast(dict[str, JsonValue], first["identity"])
    changed_identity = cast(dict[str, JsonValue], changed["identity"])
    assert first_identity["request_id"] == changed_identity["request_id"]
    assert request_digest(first_identity) == expected["first-publication"]
    assert request_digest(changed_identity) == expected["same-key-material-change-conflict"]
    assert request_digest(first_identity) != request_digest(changed_identity)
