"""Omitted empty payload reference sets (n7 RC3a, issue #1103).

n7 counted 57 of 60 trials refused because a ``claim_recorded/1.1.0`` draft left out an empty
``supersedes_claim_refs`` or ``limitation_refs`` after the tool description said to omit empty
lists. The request model now fills exactly the allowlisted sets whose omission has one meaning;
every substance-bearing list keeps its exact refusal. Each case runs the real request model the MCP
bridge, the CLI and the service share.
"""

from __future__ import annotations

from typing import cast

import pytest
from pydantic import ValidationError

from finishup.mcp.descriptors import TOOL_DESCRIPTORS
from finishup.mcp.errors import safe_validation_locations
from finishup.protocol.models import PublishWorkRequest
from finishup.protocol.publish_boilerplate import (
    PAYLOAD_EMPTY_SET_DEFAULTS,
    default_empty_payload_sets,
    normalize_publish_drafts,
)

_UUID = "00000000-0000-4000-8000-00000000000"
_IDENTITY: dict[str, object] = {
    "protocol_version": "0.1",
    "schema_version": "1.0.0",
    "request_id": f"req_{_UUID}1",
    "session_id": f"ses_{_UUID}1",
    "writer_id": f"wri_{_UUID}1",
    "actor": {"actor_id": "codex", "actor_type": "logical_agent"},
    "client": {"kind": "codex_cli", "version": "1", "integration": "cooperative_mcp"},
}


def _draft(name: str, version: str, payload: dict[str, object]) -> dict[str, object]:
    return {"schema": {"name": name, "version": version}, "payload": payload}


def _request(*drafts: dict[str, object]) -> dict[str, object]:
    return {**_IDENTITY, "event_drafts": list(drafts)}


def _claim(version: str = "1.1.0", /, **extra: object) -> dict[str, object]:
    return _draft(
        "claim_recorded",
        version,
        {
            "claim_id": f"clm_{_UUID}1",
            "claim_kind": "material",
            "statement": "The parser change is complete.",
            "supporting_refs": [f"evd_{_UUID}1"],
            **extra,
        },
    )


def _payload(request: PublishWorkRequest, index: int = 0) -> dict[str, object]:
    draft = cast(dict[str, object], request.event_drafts[index])
    return cast(dict[str, object], draft["payload"])


def _missing_fields(body: dict[str, object]) -> tuple[str, ...]:
    with pytest.raises(ValidationError) as caught:
        PublishWorkRequest.model_validate(body)
    return tuple(
        str(location["missing_fields"])
        for location in safe_validation_locations(caught.value)
        if "missing_fields" in location
    )


def test_claim_1_1_omitting_empty_limitation_and_supersedes_sets_is_admitted() -> None:
    request = PublishWorkRequest.model_validate(_request(_claim()))
    payload = _payload(request)
    assert tuple(cast(tuple[object, ...], payload["limitation_refs"])) == ()
    assert tuple(cast(tuple[object, ...], payload["supersedes_claim_refs"])) == ()


@pytest.mark.parametrize(
    "explicit",
    [
        {"limitation_refs": [], "supersedes_claim_refs": []},
        {"limitation_refs": []},
        {"supersedes_claim_refs": []},
    ],
)
def test_omitted_and_explicit_empty_sets_are_one_request(explicit: dict[str, object]) -> None:
    omitted = PublishWorkRequest.model_validate(_request(_claim()))
    spelled = PublishWorkRequest.model_validate(_request(_claim(**explicit)))
    # The JSON form is what the request digest hashes: an omitted set and ``[]`` are one request.
    assert omitted.model_dump(mode="json") == spelled.model_dump(mode="json")


def test_a_sent_value_is_never_replaced() -> None:
    high, low = f"res_{_UUID}2", f"res_{_UUID}1"
    prior = f"clm_{_UUID}9"
    request = PublishWorkRequest.model_validate(
        _request(_claim(limitation_refs=[high, low], supersedes_claim_refs=[prior]))
    )
    payload = _payload(request)
    # Kept, only canonicalized as the reference-set rule already does (#1084).
    assert list(cast(list[object], payload["limitation_refs"])) == [low, high]
    assert list(cast(list[object], payload["supersedes_claim_refs"])) == [prior]


@pytest.mark.parametrize(
    ("draft", "missing"),
    [
        # The claim's substance: an omitted supporting set is a forgotten value, not an empty one.
        (
            _draft(
                "claim_recorded",
                "1.1.0",
                {"claim_id": f"clm_{_UUID}1", "claim_kind": "material", "statement": "done"},
            ),
            "supporting_refs",
        ),
        # A revision's substance.
        (
            _draft(
                "plan_revised",
                "1.0.0",
                {"plan_version": 2, "supersedes_plan_version": 1, "reason": "r", "summary": "s"},
            ),
            "obligation_changes",
        ),
        (
            _draft(
                "plan_revised",
                "1.1.0",
                {
                    "plan_version": 2,
                    "supersedes_plan_version": 1,
                    "reason": "r",
                    "summary": "s",
                    "task_statement": "t",
                },
            ),
            "obligation_changes",
        ),
        # Without no_obligations_reason a plan's obligations are never assumed empty.
        (_draft("plan_published", "1.0.0", {"plan_version": 1, "summary": "p"}), "obligation_refs"),
        (
            _draft(
                "plan_published",
                "1.1.0",
                {"plan_version": 1, "summary": "p", "task_statement": "t"},
            ),
            "obligation_refs",
        ),
    ],
)
def test_only_allowlisted_fields_are_filled(draft: dict[str, object], missing: str) -> None:
    assert _missing_fields(_request(draft)) == (missing,)


def test_a_1_0_claim_never_gains_1_1_fields() -> None:
    request = PublishWorkRequest.model_validate(_request(_claim("1.0.0")))
    payload = _payload(request)
    assert "limitation_refs" not in payload
    assert "supersedes_claim_refs" not in payload
    # And a 1.0.0 claim that names a 1.1.0 field is still refused by its own schema.
    with pytest.raises(ValidationError):
        PublishWorkRequest.model_validate(_request(_claim("1.0.0", limitation_refs=[])))


@pytest.mark.parametrize("version", ["1.0.0", "1.1.0"])
def test_plan_obligation_refs_default_only_beside_no_obligations_reason(version: str) -> None:
    plan = _draft(
        "plan_published",
        version,
        {
            "plan_version": 1,
            "summary": "p",
            "no_obligations_reason": "single_atomic_change",
            **({"task_statement": "t"} if version == "1.1.0" else {}),
        },
    )
    request = PublishWorkRequest.model_validate(_request(plan))
    assert tuple(cast(tuple[object, ...], _payload(request)["obligation_refs"])) == ()
    spelled = PublishWorkRequest.model_validate(
        _request(
            {**plan, "payload": {**cast(dict[str, object], plan["payload"]), "obligation_refs": []}}
        )
    )
    assert request.model_dump(mode="json") == spelled.model_dump(mode="json")


def test_the_allowlist_names_only_the_reviewed_sets() -> None:
    assert dict(PAYLOAD_EMPTY_SET_DEFAULTS) == {
        ("claim_recorded", "1.1.0"): (("limitation_refs", None), ("supersedes_claim_refs", None)),
        ("plan_published", "1.0.0"): (("obligation_refs", "no_obligations_reason"),),
        ("plan_published", "1.1.0"): (("obligation_refs", "no_obligations_reason"),),
    }


@pytest.mark.parametrize("wrap", [list, tuple])
def test_normalize_returns_the_same_object_when_nothing_changes(wrap: type) -> None:
    complete = wrap([_claim(limitation_refs=[], supersedes_claim_refs=[]), _claim("1.0.0")])
    assert default_empty_payload_sets(complete) is complete
    assert normalize_publish_drafts(complete) is complete
    # Not a draft list at all: handed back for the schema to refuse.
    for value in (None, "drafts", {"schema": "x"}, wrap(["not a draft", 3])):
        assert default_empty_payload_sets(value) is value


@pytest.mark.parametrize("wrap", [list, tuple])
def test_a_filled_batch_keeps_its_container_and_other_drafts(wrap: type) -> None:
    untouched = _claim("1.0.0")
    drafts = wrap([untouched, _claim()])
    filled = default_empty_payload_sets(drafts)
    assert type(filled) is wrap
    members = cast(tuple[object, ...] | list[object], filled)
    assert members[0] is untouched
    payload = cast(dict[str, object], cast(dict[str, object], members[1])["payload"])
    assert payload["limitation_refs"] == () and payload["supersedes_claim_refs"] == ()
    # The input is never mutated.
    assert "limitation_refs" not in cast(
        dict[str, object], cast(dict[str, object], drafts[1])["payload"]
    )


def test_every_descriptor_says_exactly_what_may_be_omitted() -> None:
    """The publish_work description told agents to omit "empty lists" (n7 RC3a)."""

    for descriptors in TOOL_DESCRIPTORS.values():
        by_name = {descriptor.name: descriptor.description for descriptor in descriptors}
        publish = by_name["publish_work"]
        assert "empty lists" not in publish
        assert "empty limitation_refs and supersedes_claim_refs" in publish
        assert "evidence observed_at stays required" in publish
        assert "evidence_refs is a set: any order, sorted for you." in by_name["respond"]
        assert (
            "finishup://guidance/request-templates.md#publish-shapes" in by_name["closure_prepare"]
        )
