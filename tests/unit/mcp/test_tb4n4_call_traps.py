"""The tb4n4 call traps (issue #1049): each case replays the shape an agent actually sent.

tb4n4 counted 78 rejected FinishUP calls in 41 of 60 attempts. The shapes below are rebuilt from the
issue's census (the recorded frames stay on the maintainer's machine). Each runs the bridge's own
validation path or read_guidance dispatch; no service is contacted.
"""

from __future__ import annotations

from typing import cast

import pytest
from pydantic import ValidationError

from finishup.mcp import server as bridge
from finishup.mcp.errors import safe_validation_locations
from finishup.mcp.resources import resolve_guidance_topic_uri
from finishup.mcp.server import invalid_request_message
from finishup.protocol.guidance_uris import GUIDANCE_DOCUMENT_URIS, GUIDANCE_TOPIC_URIS
from finishup.protocol.models import PublishWorkRequest, StatusRequest

_IDENTITY: dict[str, object] = {
    "protocol_version": "0.1",
    "schema_version": "1.0.0",
    "request_id": "req_00000000-0000-4000-8000-000000000001",
    "session_id": "ses_00000000-0000-4000-8000-000000000001",
    "writer_id": "wri_00000000-0000-4000-8000-000000000001",
    "actor": {"actor_id": "codex", "actor_type": "logical_agent"},
    "client": {"kind": "codex_cli", "version": "1", "integration": "cooperative_mcp"},
}
_UUID = "00000000-0000-4000-8000-00000000000"
_SECRET = "caller-prose-must-not-echo"
_TEMPLATES = "finishup://guidance/request-templates.md"
_POLICY = "finishup://guidance/publication-policy.md"


def _request(*drafts: dict[str, object]) -> dict[str, object]:
    return {
        **_IDENTITY,
        "expected_frontier": {"sequence": "1", "head_digest": "sha256:" + "0" * 64},
        "event_drafts": list(drafts),
    }


def _draft(name: str, version: str, payload: dict[str, object], seed: int = 1) -> dict[str, object]:
    return {
        "event_id": f"evt_{_UUID}{seed}",
        "schema": {"name": name, "version": version},
        "occurred_at": "2026-01-01T00:00:00.000Z",
        "causal_parents": [],
        "payload": payload,
        "artifact_refs": [],
        "evidence_refs": [],
    }


def _rejected(request: dict[str, object]) -> str:
    with pytest.raises(ValidationError) as caught:
        PublishWorkRequest.model_validate(request)
    message = invalid_request_message("publish_work", safe_validation_locations(caught.value))
    assert _SECRET not in message
    return message


def _decision(**extra: object) -> dict[str, object]:
    return {"statement": _SECRET, "rationale": _SECRET, "authority": "codex", **extra}


# --- 1. decision_recorded with decision_id (10 attempts, extra_forbidden) -----------------------


def test_a_decision_id_is_accepted_and_ignored() -> None:
    """Every other family carries an ``<x>_id``; the agent sent one for its decision too."""

    sent = PublishWorkRequest.model_validate(
        _request(_draft("decision_recorded", "1.0.0", _decision(decision_id="dec-1")))
    )
    plain = PublishWorkRequest.model_validate(
        _request(_draft("decision_recorded", "1.0.0", _decision()))
    )
    # Dropped before anything prepares or hashes the drafts: the same request either way, so a
    # retry with or without it under one request_id is a replay, never an identity conflict.
    assert sent == plain
    assert sent.model_dump(mode="json") == plain.model_dump(mode="json")
    payload = cast(dict[str, object], cast(dict[str, object], sent.event_drafts[0])["payload"])
    assert "decision_id" not in payload


def test_only_the_decision_id_of_a_decision_is_ignored() -> None:
    # Another unknown key on a decision, and a decision_id on another family, are still refused.
    other_key = _rejected(_request(_draft("decision_recorded", "1.0.0", _decision(note=_SECRET))))
    assert "the payload carries 1 property the decision_recorded schema does not admit" in other_key
    action = _rejected(
        _request(
            _draft(
                "action_recorded",
                "1.0.0",
                {
                    "action_id": f"act_{_UUID}1",
                    "action_kind": "other",
                    "description": _SECRET,
                    "decision_id": "dec-1",
                },
            )
        )
    )
    assert "the action_recorded schema does not admit" in action


# --- 2. resolving without resolution_evidence_refs (8) ----------------------------------------


def _resolution(**extra: object) -> dict[str, object]:
    return {
        "obligation_id": f"obl_{_UUID}1",
        "description": _SECRET,
        "evidence_expectation": _SECRET,
        "status": "resolved",
        **extra,
    }


@pytest.mark.parametrize("version", ["1.0.0", "1.1.0"])
@pytest.mark.parametrize(
    "extra",
    [{}, {"resolution_evidence_refs": []}, {"resolution_evidence_refs": [f"obl_{_UUID}1"]}],
    ids=["omitted", "empty", "wrong_id_kind"],
)
def test_a_resolution_without_its_refs_names_what_goes_in_them(
    version: str, extra: dict[str, object]
) -> None:
    message = _rejected(_request(_draft("obligation_published", version, _resolution(**extra))))
    assert "resolution_evidence_refs belongs only to status resolved" in message
    assert "evidence (evd_) or result (res_) ids that show the work done" in message
    assert "repeat every other field as status view obligations shows it" in message


def test_the_obligations_view_states_the_resolution_recipe() -> None:
    from finishup.mcp.summaries import summary_for_status
    from finishup.protocol.readiness_text import (
        OBLIGATION_RESOLVE_RECIPE_VARIANTS,
        obligation_resolve_recipe_variants,
    )

    assert "resolution_evidence_refs" in OBLIGATION_RESOLVE_RECIPE_VARIANTS[0]
    assert all("status resolved" in text for text in OBLIGATION_RESOLVE_RECIPE_VARIANTS)
    assert obligation_resolve_recipe_variants([{"status": "open"}])
    assert obligation_resolve_recipe_variants([{"status": "acknowledged_not_done"}])
    assert obligation_resolve_recipe_variants([{"status": "resolved"}]) == ()
    assert obligation_resolve_recipe_variants([{"status": ["open"]}]) == ()
    text = summary_for_status(
        {
            "ok": True,
            "view": "obligations",
            "page": {
                "items": [{"obligation_id": f"obl_{_UUID}1", "status": "open"}],
                "next_cursor": None,
            },
        }
    )
    assert OBLIGATION_RESOLVE_RECIPE_VARIANTS[0] in text
    resolved_only = summary_for_status(
        {
            "ok": True,
            "view": "obligations",
            "page": {
                "items": [{"obligation_id": f"obl_{_UUID}1", "status": "resolved"}],
                "next_cursor": None,
            },
        }
    )
    assert "resolution_evidence_refs" not in resolved_only


# --- 3. guessed guidance anchors (7) ------------------------------------------------------------


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("guessed", "catalogued"),
    [
        # The GitHub-style slug of the heading "`publish_work`: decision".
        (f"{_TEMPLATES}#publish_work-decision", f"{_TEMPLATES}#publish-work-decision"),
        (f"{_TEMPLATES}#Publish-Work-Decision", f"{_TEMPLATES}#publish-work-decision"),
        # The explicit anchors the documents write beside their headings.
        (f"{_POLICY}#attempt-accounting", f"{_POLICY}#requested-items-and-attempt-accounting"),
        (f"{_POLICY}#set-valued-lists", f"{_POLICY}#set-valued-reference-lists"),
        # Words that only one catalogued anchor of the document contains.
        (f"{_TEMPLATES}#decision", f"{_TEMPLATES}#publish-work-decision"),
        (
            f"{_TEMPLATES}#publish-work-obligation",
            f"{_TEMPLATES}#publish-work-plan-plus-obligation",
        ),
        (f"{_POLICY}#resolution", f"{_POLICY}#obligation-resolution"),
        # tb4n5 (#1049): the guesses agents made, now explicit stable aliases. The bare family
        # prefix reads the overview that lists every publish_work template's exact URI, and the
        # resource description's phrase reads the same overview.
        (f"{_TEMPLATES}#publish-work", f"{_TEMPLATES}#publication-templates"),
        (f"{_TEMPLATES}#publish_work", f"{_TEMPLATES}#publication-templates"),
        (f"{_TEMPLATES}#ordinary-publication", f"{_TEMPLATES}#publication-templates"),
        (f"{_TEMPLATES}#plan-and-obligations", f"{_TEMPLATES}#publish-work-plan-plus-obligation"),
        (f"{_POLICY}#plan-and-obligations", f"{_POLICY}#obligations-evidence-and-claims"),
    ],
)
async def test_a_guessed_anchor_that_names_one_topic_reads_it(
    guessed: str, catalogued: str
) -> None:
    assert catalogued in GUIDANCE_TOPIC_URIS
    assert resolve_guidance_topic_uri(guessed) == catalogued
    runtime = bridge.build_bridge_runtime("policy", host_profile="codex")
    try:
        result = await bridge.dispatch_read_guidance({"uri": guessed}, runtime)
    finally:
        await bridge.close_bridge_runtime(runtime)
    assert result.isError is False
    structured = cast(dict[str, object], result.structuredContent)
    # The result names the catalogued topic it read, never the guess.
    assert structured["uri"] == catalogued


@pytest.mark.anyio
@pytest.mark.parametrize(
    "guessed",
    [
        # Ambiguous: several catalogued anchors contain every word.
        f"{_TEMPLATES}#publish-work-coordination",
        f"{_TEMPLATES}#claim",
        # No catalogued anchor contains every word.
        f"{_TEMPLATES}#publish_work-plan-revision",
        f"{_TEMPLATES}#zz-guessed-anchor",
        # Focused topics and unknown documents carry no anchors.
        "finishup://guidance/publication.md#attempt-accounting",
        "finishup://guidance/not-a-document.md#decision",
        f"{_TEMPLATES}#",
    ],
)
async def test_an_ambiguous_or_unknown_anchor_is_still_refused(guessed: str) -> None:
    assert resolve_guidance_topic_uri(guessed) is None
    runtime = bridge.build_bridge_runtime("policy", host_profile="codex")
    try:
        result = await bridge.dispatch_read_guidance({"uri": guessed}, runtime)
    finally:
        await bridge.close_bridge_runtime(runtime)
    assert result.isError is True
    error = cast(dict[str, object], cast(dict[str, object], result.structuredContent)["error"])
    assert error["code"] == "INVALID_REQUEST"
    assert error["safe_details"] == {"field": "/uri"}


def test_every_catalogued_topic_resolves_to_itself() -> None:
    for uri in GUIDANCE_TOPIC_URIS:
        document = uri.partition("#")[0]
        if document in GUIDANCE_DOCUMENT_URIS:
            assert resolve_guidance_topic_uri(uri) == uri


# --- 5. result evidence_refs given res_ ids (6) --------------------------------------------------


def test_a_result_id_in_result_evidence_refs_names_every_place_it_does_go() -> None:
    message = _rejected(
        _request(
            _draft(
                "result_recorded",
                "1.0.0",
                {
                    "result_id": f"res_{_UUID}1",
                    "action_id": f"act_{_UUID}1",
                    "outcome": "success",
                    "summary": _SECRET,
                    "evidence_refs": [f"res_{_UUID}2"],
                },
            )
        )
    )
    assert "a result's evidence_refs names only evidence ids (evd_)" in message
    assert "or an obligation's resolution_evidence_refs" in message


# --- 7. status limit sent as an integer (4) -----------------------------------------------------


@pytest.mark.parametrize("limit", [1, 20, 100])
def test_an_integer_limit_is_read_as_its_decimal_string(limit: int) -> None:
    sent = StatusRequest.model_validate({**_IDENTITY, "view": "obligations", "limit": limit})
    canonical = StatusRequest.model_validate(
        {**_IDENTITY, "view": "obligations", "limit": str(limit)}
    )
    assert sent == canonical
    assert sent.model_dump(mode="json")["limit"] == str(limit)


@pytest.mark.parametrize("limit", [0, 101, True, 20.0, -1])
def test_an_out_of_range_or_non_integer_limit_is_still_refused(limit: object) -> None:
    with pytest.raises(ValidationError) as caught:
        StatusRequest.model_validate({**_IDENTITY, "view": "obligations", "limit": limit})
    locations = safe_validation_locations(caught.value)
    assert locations == ({"field": "/limit", "reason": "invalid_type_or_value"},)
    assert 'limit is a decimal string from "1" to "100"' in invalid_request_message(
        "status", locations
    )
