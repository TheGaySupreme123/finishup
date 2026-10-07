"""One provider judgment contract: schema generation, normalization, and failure classes."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import httpx
import pytest
from jsonschema import Draft202012Validator
from pydantic import TypeAdapter, ValidationError

from yoetz.adapters.providers.local_model import (
    LocalModelEndpointProfile,
    normalize_local_response,
)
from yoetz.adapters.providers.openai_chat_completions import (
    ChatCompletionsProfile,
)
from yoetz.adapters.providers.openai_chat_completions import (
    normalize_response as normalize_chat_response,
)
from yoetz.adapters.providers.openai_responses import (
    CHALLENGE_FIELD_GLOSSARY,
    FINDING_KIND_GLOSSARY,
    JUDGMENT_JSON_SCHEMA,
    MISSING_ITEM_FIELD_GLOSSARY,
    MISSING_ITEM_KIND_GLOSSARY,
    STRICT_JUDGMENT_JSON_SCHEMA,
    VERDICT_FIELD_GLOSSARY,
    VERIFIED_FIELD_GLOSSARY,
    JudgmentValidationError,
    OpenAIProfile,
    build_judgment_json_schema,
    classify_provider_failure,
    normalize_judgment,
    owner_declared_data_use_profile,
)
from yoetz.adapters.providers.openai_responses import (
    normalize_response as normalize_responses_response,
)
from yoetz.domain.findings import (
    EXTERNAL_SEMANTIC_FINDING_KINDS,
    RUNTIME_FAILURE_STAGES,
    FindingKind,
    SemanticFailureClass,
)
from yoetz.ports.semantic import (
    SemanticResultInvalid,
    SemanticResultRefused,
    SemanticResultSuccess,
    SemanticResultTimeout,
)
from yoetz.protocol.canonical import JsonValue, canonical_digest, strict_json_parse
from yoetz.protocol.models import (
    ProviderChallengeModel,
    ProviderJudgmentEnvelopeModel,
    ProviderJudgmentModel,
)

_NOW = datetime(2026, 7, 28, tzinfo=UTC)
_DIGEST = "sha256:" + "c" * 64
_REPO = Path(__file__).resolve().parents[4]
_FROZEN_SCHEMA = _REPO / "schemas" / "findings" / "provider-judgment-1.1.0.schema.json"
_ACTIVE_SCHEMA = _REPO / "schemas" / "findings" / "provider-judgment-1.2.0.schema.json"
_RELEASED_1_0_SCHEMA = _REPO / "schemas" / "findings" / "provider-judgment-1.0.0.schema.json"

_REF_A = "clm_20000000-0000-4000-8000-000000000001"
_REF_B = "act_10000000-0000-4000-8000-000000000001"
_REF_C = "evd_30000000-0000-4000-8000-000000000001"


def _challenge(
    *,
    kind: str = "claim_without_admissible_evidence",
    refs: list[str] | None = None,
    summary: str = "Evidence gap",
) -> dict[str, JsonValue]:
    return {
        "finding_kind": kind,
        "summary": summary,
        "cited_refs": cast(list[JsonValue], refs if refs is not None else [_REF_A]),
        "discrepancy": "The claim lacks a recorded basis.",
        "alternative_interpretation": "The claim may remain unresolved.",
        "message_to_main_agent": "Main agent: provide evidence for the claim.",
        "requested_next_step": "provide_evidence",
        "uncertainty": "The missing material may exist outside the case.",
        "snippet": "The claim lacks a recorded basis.",
    }


def _missing(
    kind: str = "verification_output",
    refs: list[str] | None = None,
    reason: str = "The test output that the completion claim cites is not in the packet.",
) -> dict[str, JsonValue]:
    return {
        "kind": kind,
        "target_refs": cast(list[JsonValue], [_REF_A] if refs is None else refs),
        "reason": reason,
    }


def _judgment(
    conclusion: str = "no_material_discrepancy",
    challenges: list[dict[str, JsonValue]] | None = None,
    missing: list[dict[str, JsonValue]] | None = None,
) -> dict[str, JsonValue]:
    body: dict[str, JsonValue] = {
        "conclusion": conclusion,
        "review_summary": "The supplied packet was reviewed.",
        "verified": [],
        "reviewer_challenges": cast(list[JsonValue], [] if challenges is None else challenges),
        "prior_finding_verdicts": [],
    }
    if missing is not None:
        body["missing_for_assessment"] = cast(list[JsonValue], missing)
    elif conclusion == "insufficient_packet":
        body["missing_for_assessment"] = [cast(JsonValue, _missing())]
    return body


def _provider_schema_accepts(value: JsonValue) -> bool:
    """Validate a bare judgment against the request schema, which asks for the envelope."""

    validator = cast(Any, Draft202012Validator(JUDGMENT_JSON_SCHEMA))
    return cast(bool, validator.is_valid({"judgment": value}))


def _responses_profile() -> OpenAIProfile:
    return OpenAIProfile(
        provider_id="openai",
        model="gpt-test",
        endpoint_profile_id="openai-responses",
        endpoint_profile_version="1.0.0",
        timeout_seconds=60,
        supports_structured_outputs=True,
        data_use_profile=owner_declared_data_use_profile(
            reviewed_at=_NOW,
            expires_at=_NOW + timedelta(days=30),
            evidence_digest=_DIGEST,
        ),
    )


def _chat_profile() -> ChatCompletionsProfile:
    return ChatCompletionsProfile(
        provider_id="xai",
        model="grok-test",
        endpoint_profile_id="xai-openai-chat-completions",
        endpoint_profile_version="1.0.0",
        timeout_seconds=60,
        structured_output_enforcement="provider_enforced",
        data_use_profile=owner_declared_data_use_profile(
            reviewed_at=_NOW,
            expires_at=_NOW + timedelta(days=30),
            evidence_digest=_DIGEST,
        ),
        host="api.x.ai",
    )


def _local_profile() -> LocalModelEndpointProfile:
    return LocalModelEndpointProfile(
        profile_id="local-test",
        profile_version="1.0.0",
        endpoint_profile_id="local-test-endpoint",
        endpoint_profile_version="1.0.0",
        model="local-test-model",
        protocol_version="1.0.0",
        judgment_schema_version="1.2.0",
        timeout_seconds=30,
        expected_service_identity="local-test-service",
        expected_owner_uid=0,
        expected_peer_uid=0,
        expected_socket_mode=0o600,
        release_resource_digest=_DIGEST,
        capability_evidence_digest=_DIGEST,
    )


class _ResponsesResponse:
    def __init__(
        self,
        *,
        output_text: str | None = None,
        status: str = "completed",
        refusal: str | None = None,
        response_id: str = "resp_test",
    ) -> None:
        self.output_text = output_text
        self.status = status
        self.refusal = refusal
        self.id = response_id


class _ChatMessage:
    def __init__(self, *, content: str | None = None, refusal: str | None = None) -> None:
        self.content = content
        self.refusal = refusal


class _ChatChoice:
    def __init__(self, message: _ChatMessage, finish_reason: str | None = "stop") -> None:
        self.message = message
        self.finish_reason = finish_reason


class _ChatResponse:
    def __init__(self, choice: _ChatChoice | None = None, response_id: str = "chatcmpl-1") -> None:
        self.choices = () if choice is None else (choice,)
        self.id = response_id


def test_generated_schema_matches_owning_model_and_frozen_artifact() -> None:
    rebuilt = build_judgment_json_schema()
    assert rebuilt == JUDGMENT_JSON_SCHEMA
    assert canonical_digest(rebuilt) == canonical_digest(JUDGMENT_JSON_SCHEMA)

    active = strict_json_parse(_ACTIVE_SCHEMA.read_bytes())
    assert type(active) is dict
    frozen_doc = cast(dict[str, Any], active)
    # The active catalog adds $id/$schema/root title; after dropping catalog chrome and nested
    # titles, the constrained-output body matches the runtime request schema byte-for-byte.
    assert frozen_doc["$id"].endswith("provider-judgment-1.2.0.schema.json")

    def _strip_titles(node: object) -> object:
        # The catalog artifact keeps title/description chrome for human readers; the request
        # schema carries shape only, so both annotations are dropped before comparing.
        if type(node) is dict:
            return {
                key: _strip_titles(value)
                for key, value in cast(dict[str, object], node).items()
                if key not in {"title", "description"}
            }
        if type(node) is list:
            return [_strip_titles(item) for item in cast(list[object], node)]
        return node

    frozen_body = {
        key: value
        for key, value in cast(dict[str, object], _strip_titles(frozen_doc)).items()
        if key not in {"$id", "$schema"}
    }
    # The request schema carries curated reviewer definitions the frozen catalog does not; both
    # sides drop annotations so what is compared is the shape the two documents must share.
    assert frozen_body == _strip_titles(cast(dict[str, object], JUDGMENT_JSON_SCHEMA))
    kinds = cast(
        list[str],
        cast(
            dict[str, Any], cast(dict[str, Any], JUDGMENT_JSON_SCHEMA["$defs"])["FindingKindWire"]
        )["enum"],
    )
    assert set(kinds) == {kind.value for kind in EXTERNAL_SEMANTIC_FINDING_KINDS}
    assert FindingKind.COORDINATION_OVERLAP.value not in kinds


def test_request_schema_root_is_an_object_never_a_union() -> None:
    """A constrained-output root must be an object; a root union fails the request outright.

    Regression guard: generating the request schema straight from the ``ProviderJudgmentModel``
    union puts ``anyOf`` at the root. Providers reject that schema before generation starts, and
    the rejection reaches the ledger only as an opaque transport failure, so no test that exercises
    parsing or normalization can see it. This asserts the wire shape itself.
    """

    assert JUDGMENT_JSON_SCHEMA.get("type") == "object"
    assert "anyOf" not in JUDGMENT_JSON_SCHEMA
    assert "oneOf" not in JUDGMENT_JSON_SCHEMA
    assert "allOf" not in JUDGMENT_JSON_SCHEMA
    assert "$ref" not in JUDGMENT_JSON_SCHEMA
    assert JUDGMENT_JSON_SCHEMA.get("additionalProperties") is False

    # Every object in the document, including union branches, stays closed and fully required.
    def _walk(node: object, path: str) -> None:
        if type(node) is dict:
            source = cast(dict[str, Any], node)
            if source.get("type") == "object":
                assert source.get("additionalProperties") is False, path
                properties = cast(dict[str, Any], source.get("properties", {}))
                required = cast(list[str], source.get("required", []))
                # Conditional snippet requirements are expressed with allOf on the active
                # verified-item contract; the base property is intentionally optional.
                optional: set[str] = {"snippet"} if path.endswith("ProviderVerifiedItem") else set()
                # ``restates`` (issue #980) is an optional link; strict output still sends it as
                # a required nullable field (``strict_output_schema``).
                if path.endswith("ProviderChallenge"):
                    optional.add("restates")
                assert set(properties) - optional == set(required), path
            for key, value in source.items():
                if key in {"properties", "$defs"}:
                    for name, child in cast(dict[str, Any], value).items():
                        _walk(child, f"{path}.{key}.{name}")
                else:
                    _walk(value, f"{path}.{key}")
        elif type(node) is list:
            for index, item in enumerate(cast(list[Any], node)):
                _walk(item, f"{path}[{index}]")

    _walk(JUDGMENT_JSON_SCHEMA, "$")


def test_strict_wire_schema_uses_only_the_strict_structured_output_subset() -> None:
    """Every provider request sends a schema that ``strict: true`` structured output admits.

    Regression guard: provider-judgment 1.2.0 expressed the verified-row snippet rule with
    ``allOf``/``if``/``then``/``not`` and Pydantic ``default`` values. gpt-6-luna rejected that
    request schema with a 400 before generation, which the Codex runtime surfaced only as an
    opaque failed turn, so every semantic review failed. The wire form must carry none of the
    rejected keywords and list every property of every object as required.
    """

    rejected = {"allOf", "default", "if", "not", "then", "uniqueItems"}

    def _walk(node: object, path: str) -> None:
        if type(node) is dict:
            source = cast(dict[str, Any], node)
            assert not rejected & set(source), path
            if source.get("type") == "object":
                assert source.get("additionalProperties") is False, path
                properties = cast(dict[str, Any], source.get("properties", {}))
                assert set(properties) == set(cast(list[str], source.get("required", []))), path
            for key, value in source.items():
                if key in {"properties", "$defs"}:
                    for name, child in cast(dict[str, Any], value).items():
                        _walk(child, f"{path}.{key}.{name}")
                else:
                    _walk(value, f"{path}.{key}")
        elif type(node) is list:
            for index, item in enumerate(cast(list[Any], node)):
                _walk(item, f"{path}[{index}]")

    _walk(STRICT_JUDGMENT_JSON_SCHEMA, "$")
    verified = cast(dict[str, Any], STRICT_JUDGMENT_JSON_SCHEMA["$defs"])["ProviderVerifiedItem"]
    assert verified["properties"]["snippet"]["type"] == ["string", "null"]
    # The owning contract keeps the conditional rule; only the wire form drops it.
    assert "allOf" in cast(dict[str, Any], JUDGMENT_JSON_SCHEMA["$defs"])["ProviderVerifiedItem"]


def test_strict_wire_output_with_null_snippet_decodes_under_the_contract() -> None:
    ref = "evt_00000000-0000-4000-8000-000000000001"
    body: dict[str, Any] = {
        "judgment": {
            "conclusion": "no_material_discrepancy",
            "review_summary": "Checked both rows.",
            "prior_finding_verdicts": [],
            "reviewer_challenges": [],
            "verified": [
                {
                    "requirement_or_claim": "Supported row",
                    "verdict": "supported",
                    "cited_refs": [ref],
                    "snippet": "quoted",
                },
                {
                    "requirement_or_claim": "Unassessable row",
                    "verdict": "not_assessable",
                    "cited_refs": [ref],
                    "snippet": None,
                },
            ],
        }
    }
    cast(Any, Draft202012Validator(STRICT_JUDGMENT_JSON_SCHEMA)).validate(body)
    judgment = normalize_judgment(cast(JsonValue, body), require_part2=True)
    assert judgment.conclusion == "no_material_discrepancy"

    missing_quote = json.loads(json.dumps(body))
    missing_quote["judgment"]["verified"][0]["snippet"] = None
    # Strict output allows this shape; the row is dropped and counted, never the whole review.
    degraded = normalize_judgment(cast(JsonValue, missing_quote), require_part2=True)
    assert degraded.verified_dropped == 1
    assert [item.verdict for item in degraded.verified] == ["not_assessable"]


def test_request_schema_carries_no_docstring_commentary() -> None:
    """Developer docstrings explain the contract to maintainers, never to the provider.

    The schema does carry descriptions now, but only the curated reviewer definitions written for
    the model. Every one must come from the glossary; a pydantic docstring reaching the wire — the
    thing ``_strip_schema_titles`` exists to prevent — fails here.
    """

    def _annotations(node: object, key_name: str) -> list[object]:
        found: list[object] = []
        if type(node) is dict:
            for key, value in cast(dict[str, Any], node).items():
                if key == key_name:
                    found.append(value)
                found.extend(_annotations(value, key_name))
        elif type(node) is list:
            for item in cast(list[Any], node):
                found.extend(_annotations(item, key_name))
        return found

    assert _annotations(JUDGMENT_JSON_SCHEMA, "title") == []

    curated = (
        set(CHALLENGE_FIELD_GLOSSARY.values())
        | set(VERIFIED_FIELD_GLOSSARY.values())
        | set(VERDICT_FIELD_GLOSSARY.values())
        | set(MISSING_ITEM_FIELD_GLOSSARY.values())
    )
    descriptions = _annotations(JUDGMENT_JSON_SCHEMA, "description")
    assert descriptions
    assert set(descriptions) <= curated

    docstrings = {
        (model.__doc__ or "").strip()
        for model in (
            ProviderChallengeModel,
            ProviderJudgmentEnvelopeModel,
        )
    } - {""}
    assert docstrings
    assert not docstrings & set(descriptions)


def test_every_provider_finding_kind_and_challenge_field_has_a_reviewer_gloss() -> None:
    """A provider kind or field the model can emit but has no definition is an unfair question.

    Adding a provider-wire kind or a challenge field without writing its gloss fails here rather
    than reaching a provider as one more bare token among the rest. Local coordination kinds are
    intentionally excluded by the D7 external semantic boundary.
    """

    assert set(FINDING_KIND_GLOSSARY) == {kind.value for kind in EXTERNAL_SEMANTIC_FINDING_KINDS}
    challenge = cast(
        dict[str, Any], cast(dict[str, Any], JUDGMENT_JSON_SCHEMA["$defs"])["ProviderChallenge"]
    )
    assert set(CHALLENGE_FIELD_GLOSSARY) == set(cast(dict[str, Any], challenge["properties"]))

    kind_gloss = cast(
        dict[str, Any], cast(dict[str, Any], JUDGMENT_JSON_SCHEMA["$defs"])["FindingKindWire"]
    )["description"]
    for kind in EXTERNAL_SEMANTIC_FINDING_KINDS:
        assert f"{kind.value}: " in kind_gloss


def test_envelope_and_bare_judgment_both_normalize() -> None:
    """The schema asks for the envelope; a provider that flattens it is still admitted."""

    bare = _judgment("challenges_returned", [_challenge()])
    enveloped: dict[str, JsonValue] = {"judgment": cast(JsonValue, bare)}
    assert normalize_judgment(bare) == normalize_judgment(enveloped)
    assert _provider_schema_accepts(bare)


def test_every_provider_finding_kind_is_admitted_and_local_kinds_are_rejected() -> None:
    for kind in EXTERNAL_SEMANTIC_FINDING_KINDS:
        judgment = normalize_judgment(
            _judgment("challenges_returned", [_challenge(kind=kind.value)])
        )
        assert judgment.challenges[0].finding_kind is kind

    with pytest.raises(ValueError, match="openai_judgment_shape_invalid"):
        normalize_judgment(
            _judgment(
                "challenges_returned",
                [_challenge(kind=FindingKind.COORDINATION_OVERLAP.value)],
            )
        )

    with pytest.raises(ValueError, match="openai_judgment_shape_invalid"):
        normalize_judgment(
            _judgment("challenges_returned", [_challenge(kind="claim_without_evidence")])
        )
    with pytest.raises(ValueError, match="openai_judgment_shape_invalid"):
        normalize_judgment(_judgment("challenges_returned", [_challenge(kind="not_a_kind")]))


def test_challenge_refs_enforce_pattern_count_uniqueness_and_canonicalize_order() -> None:
    # Valid unsorted refs normalize into ASCII order.
    judgment = normalize_judgment(
        _judgment(
            "challenges_returned",
            [_challenge(refs=[_REF_C, _REF_A, _REF_B])],
        )
    )
    assert judgment.challenges[0].cited_refs == tuple(sorted((_REF_A, _REF_B, _REF_C)))

    with pytest.raises(ValueError, match="openai_judgment_shape_invalid"):
        normalize_judgment(_judgment("challenges_returned", [_challenge(refs=[])]))
    with pytest.raises(ValueError, match="openai_judgment_shape_invalid"):
        normalize_judgment(_judgment("challenges_returned", [_challenge(refs=[_REF_A, _REF_A])]))
    with pytest.raises(ValueError, match="openai_judgment_shape_invalid"):
        normalize_judgment(
            _judgment("challenges_returned", [_challenge(refs=["task_not_a_subject_id"])])
        )
    with pytest.raises(ValueError, match="openai_judgment_shape_invalid"):
        normalize_judgment(
            _judgment(
                "challenges_returned",
                [_challenge(refs=["tsk_20000000-0000-4000-8000-000000000001"])],
            )
        )
    with pytest.raises(ValueError, match="openai_judgment_shape_invalid"):
        normalize_judgment(
            _judgment(
                "challenges_returned",
                [_challenge(refs=["prose citation to the claim"])],
            )
        )


def test_provider_schema_and_consumer_both_reject_duplicate_refs() -> None:
    duplicate = _judgment(
        "challenges_returned",
        [_challenge(refs=[_REF_A, _REF_A])],
    )
    assert not _provider_schema_accepts(duplicate)
    with pytest.raises(ValueError, match="openai_judgment_shape_invalid"):
        normalize_judgment(duplicate)


def test_provider_schema_text_bound_always_fits_consumer_utf8_limit() -> None:
    admitted = _judgment(
        "challenges_returned",
        [_challenge(summary="😀" * 1024)],
    )
    assert _provider_schema_accepts(admitted)
    normalize_judgment(admitted)

    oversized = _judgment(
        "challenges_returned",
        [_challenge(summary="😀" * 1025)],
    )
    assert not _provider_schema_accepts(oversized)
    with pytest.raises(ValueError, match="openai_judgment_shape_invalid"):
        normalize_judgment(oversized)


def test_conclusion_challenge_coupling_is_enforced() -> None:
    normalize_judgment(_judgment("no_material_discrepancy", []))
    normalize_judgment(_judgment("insufficient_packet", []))
    normalize_judgment(_judgment("challenges_returned", [_challenge()]))

    with pytest.raises(ValueError, match="openai_judgment_shape_invalid"):
        normalize_judgment(_judgment("challenges_returned", []))
    with pytest.raises(ValueError, match="openai_judgment_shape_invalid"):
        normalize_judgment(_judgment("insufficient_packet", [_challenge()]))
    with pytest.raises(ValueError, match="openai_judgment_shape_invalid"):
        normalize_judgment(_judgment("no_material_discrepancy", [_challenge()]))


def test_empty_review_text_is_rejected() -> None:
    with pytest.raises(ValueError, match="openai_judgment_shape_invalid"):
        normalize_judgment(_judgment("challenges_returned", [_challenge(summary="")]))


def test_provider_model_and_normalize_share_rejection_surface() -> None:
    adapter: TypeAdapter[ProviderJudgmentModel] = TypeAdapter(ProviderJudgmentModel)
    bad = _judgment("challenges_returned", [_challenge(kind="invented_kind")])
    with pytest.raises(ValidationError):
        adapter.validate_python(bad)
    with pytest.raises(ValueError, match="openai_judgment_shape_invalid"):
        normalize_judgment(bad)


@pytest.mark.parametrize(
    ("raw", "failure_class"),
    (
        ("", SemanticFailureClass.RESPONSE_SCHEMA),
        ("```json\n{}\n```", SemanticFailureClass.RESPONSE_SCHEMA),
        (
            'prefix {"conclusion":"no_material_discrepancy","reviewer_challenges":[],"prior_finding_verdicts":[]}',
            SemanticFailureClass.RESPONSE_SCHEMA,
        ),
        (
            '{"conclusion":"no_material_discrepancy","reviewer_challenges":[],"conclusion":"x"}',
            SemanticFailureClass.RESPONSE_SCHEMA,
        ),
        (
            '{"conclusion":"no_material_discrepancy","reviewer_challenges":[],"x":1.5}',
            SemanticFailureClass.RESPONSE_SCHEMA,
        ),
    ),
)
def test_malformed_output_keeps_schema_failure_class_without_plaintext(
    raw: str, failure_class: SemanticFailureClass
) -> None:
    result = normalize_responses_response(
        _ResponsesResponse(output_text=raw),
        _responses_profile(),
        policy_digest=_DIGEST,
        latency_ms=5,
    )
    assert type(result) is SemanticResultInvalid
    assert result.provenance.failure_class is failure_class
    # No diagnostic field retains provider plaintext (slots-only structural facts).
    assert result.raw_size == len(raw.encode("utf-8"))
    for value in (
        result.provenance.provider,
        result.provenance.model,
        result.provenance.provider_request_id,
        result.provenance.failure_class,
    ):
        if type(value) is str:
            assert "conclusion" not in value
            assert "```" not in value
            assert "prefix" not in value


def test_oversized_output_is_content_invalid_not_timeout() -> None:
    huge = "x" * (1_048_576 + 8)
    result = normalize_responses_response(
        _ResponsesResponse(output_text=huge),
        _responses_profile(),
        policy_digest=_DIGEST,
        latency_ms=5,
    )
    assert type(result) is SemanticResultInvalid
    assert result.provenance.failure_class is SemanticFailureClass.RESPONSE_CONTENT


def test_incomplete_is_content_invalid_not_timeout() -> None:
    result = normalize_responses_response(
        _ResponsesResponse(output_text='{"conclusion":', status="incomplete"),
        _responses_profile(),
        policy_digest=_DIGEST,
        latency_ms=16_000,
    )
    assert type(result) is SemanticResultInvalid
    assert result.provenance.failure_class is SemanticFailureClass.RESPONSE_CONTENT
    assert result.provenance.provider_request_id == "resp_test"
    assert type(result) is not SemanticResultTimeout


def test_cancelled_is_refused_not_timeout() -> None:
    result = normalize_responses_response(
        _ResponsesResponse(status="cancelled"),
        _responses_profile(),
        policy_digest=_DIGEST,
        latency_ms=5,
    )
    assert type(result) is SemanticResultRefused


def test_chat_length_finish_reason_is_content_invalid() -> None:
    result = normalize_chat_response(
        _ChatResponse(_ChatChoice(_ChatMessage(content='{"conclusion":'), finish_reason="length")),
        _chat_profile(),
        policy_digest=_DIGEST,
        latency_ms=5,
    )
    assert type(result) is SemanticResultInvalid
    assert result.provenance.failure_class is SemanticFailureClass.RESPONSE_CONTENT


def test_transport_timeout_still_maps_to_provider_timeout() -> None:
    result = classify_provider_failure(
        httpx.TimeoutException("deadline"),
        _responses_profile(),
        policy_digest=_DIGEST,
        latency_ms=60_000,
    )
    assert type(result) is SemanticResultTimeout
    assert result.provenance.failure_class is SemanticFailureClass.TIMEOUT


def test_conforming_challenge_response_succeeds_on_first_parse() -> None:
    body = json.dumps(
        _judgment(
            "challenges_returned",
            [_challenge(refs=[_REF_B, _REF_A])],
        ),
        separators=(",", ":"),
    )
    result = normalize_responses_response(
        _ResponsesResponse(output_text=body),
        _responses_profile(),
        policy_digest=_DIGEST,
        latency_ms=12,
    )
    assert type(result) is SemanticResultSuccess
    assert result.judgment.conclusion == "challenges_returned"
    assert result.judgment.challenges[0].cited_refs == (
        _REF_B,
        _REF_A,
    ) or result.judgment.challenges[0].cited_refs == tuple(sorted((_REF_A, _REF_B)))


def test_local_normalizer_requires_the_active_part2_fields() -> None:
    profile = _local_profile()
    legacy: dict[str, JsonValue] = {
        "conclusion": "no_material_discrepancy",
        "reviewer_challenges": [],
        "prior_finding_verdicts": [],
    }
    rejected = normalize_local_response(
        json.dumps(legacy, separators=(",", ":")).encode(),
        profile,
        policy_digest=_DIGEST,
        latency_ms=4,
    )
    assert type(rejected) is SemanticResultInvalid
    accepted = normalize_local_response(
        json.dumps(_judgment(), separators=(",", ":")).encode(),
        profile,
        policy_digest=_DIGEST,
        latency_ms=4,
    )
    assert type(accepted) is SemanticResultSuccess


@pytest.mark.parametrize(
    ("parsed", "stage"),
    [
        (["not-an-object"], "envelope_invalid"),
        ({"result": _judgment()}, "envelope_invalid"),
        ({"judgment": "prose"}, "envelope_invalid"),
        ({"judgment": _judgment(), "extra": 1}, "envelope_invalid"),
        (_judgment("maybe"), "enum_invalid"),
        (_judgment("challenges_returned", [_challenge(kind="hunch")]), "enum_invalid"),
        (_judgment("challenges_returned", [_challenge(refs=[_REF_A, _REF_A])]), "refs_duplicate"),
        (_judgment("challenges_returned", [_challenge(refs=["item-1"])]), "refs_invalid"),
        (_judgment("challenges_returned", [_challenge(refs=[])]), "refs_invalid"),
        (_judgment("challenges_returned", []), "conclusion_mismatch"),
        (_judgment("no_material_discrepancy", [_challenge()]), "conclusion_mismatch"),
        (_judgment("insufficient_packet", [_challenge()]), "conclusion_mismatch"),
        (_judgment("challenges_returned", [_challenge(summary="")]), "text_bounds"),
        (_judgment("challenges_returned", [_challenge(summary="x" * 9000)]), "text_bounds"),
        ({**_judgment(), "note": "extra"}, "shape_invalid"),
        (
            _judgment("no_material_discrepancy", cast(list[dict[str, JsonValue]], "none")),
            "shape_invalid",
        ),
    ],
)
def test_rejected_judgments_carry_one_closed_validation_stage(
    parsed: JsonValue, stage: str
) -> None:
    with pytest.raises(JudgmentValidationError, match="openai_judgment_shape_invalid") as info:
        normalize_judgment(parsed)
    assert info.value.stage == stage
    # Every stage token doubles as the ``judgment_<stage>`` runtime-evidence member.
    assert f"judgment_{stage}" in RUNTIME_FAILURE_STAGES


# --- Issue #907: an unassessable packet must name what was missing -----------------------------


def test_insufficient_packet_naming_nothing_is_read_backward_not_rejected() -> None:
    """The request schema requires the list; a 1.0.0-shape reply still keeps its rulings.

    A local model or prompt-only host may answer ``insufficient_packet`` without naming what was
    missing. Rejecting the whole judgment would also discard #905's rulings, so the consumer reads
    it with no items and the check discloses the unnamed request.
    """

    ruling: dict[str, JsonValue] = {
        "finding_id": "fnd_866db2dd-0000-4000-8000-000000000001",
        "verdict": "still_present",
        "cited_refs": [_REF_C],
        "note": "The failing lookup still has no regression result.",
    }
    bare = _judgment("insufficient_packet")
    del bare["missing_for_assessment"]
    bare["prior_finding_verdicts"] = [ruling]
    empty = {**_judgment("insufficient_packet", missing=[]), "prior_finding_verdicts": [ruling]}
    for value in (bare, empty):
        assert not _provider_schema_accepts(cast(JsonValue, value))
        for parsed in (value, {"judgment": value}):
            judgment = normalize_judgment(cast(JsonValue, parsed))
            assert judgment.conclusion == "insufficient_packet"
            assert judgment.missing_for_assessment == ()
            assert [item.verdict for item in judgment.prior_finding_verdicts] == ["still_present"]
    assert _provider_schema_accepts(cast(JsonValue, _judgment("insufficient_packet")))
    # Reading it backward never admits what the insufficient branch forbids.
    with pytest.raises(JudgmentValidationError) as info:
        normalize_judgment(
            cast(JsonValue, {**bare, "reviewer_challenges": [cast(JsonValue, _challenge())]})
        )
    assert info.value.stage == "conclusion_mismatch"


def test_an_empty_missing_list_beside_another_conclusion_is_the_absent_list() -> None:
    for conclusion, challenges in (
        ("no_material_discrepancy", []),
        ("challenges_returned", [_challenge()]),
    ):
        judgment = normalize_judgment(
            cast(JsonValue, _judgment(conclusion, challenges, missing=[]))
        )
        assert judgment.conclusion == conclusion
        assert len(judgment.challenges) == len(challenges)
        assert judgment.missing_for_assessment == ()


def test_only_insufficient_packet_may_name_missing_items() -> None:
    for conclusion, challenges in (
        ("no_material_discrepancy", []),
        ("challenges_returned", [_challenge()]),
    ):
        value = _judgment(conclusion, challenges, missing=[_missing()])
        assert not _provider_schema_accepts(cast(JsonValue, value))
        with pytest.raises(JudgmentValidationError) as info:
            normalize_judgment(cast(JsonValue, value))
        assert info.value.stage == "conclusion_mismatch"


def test_missing_items_normalize_with_canonical_refs_and_bounded_reason() -> None:
    judgment = normalize_judgment(
        _judgment(
            "insufficient_packet",
            missing=[
                _missing("current_diff_for_path", [_REF_C, _REF_A]),
                _missing("task_statement", []),
            ],
        )
    )
    assert judgment.conclusion == "insufficient_packet"
    assert [(item.kind, item.target_refs) for item in judgment.missing_for_assessment] == [
        ("current_diff_for_path", tuple(sorted((_REF_C, _REF_A), key=str.encode))),
        ("task_statement", ()),
    ]


@pytest.mark.parametrize(
    ("missing", "stage"),
    [
        (_missing("invented_kind"), "enum_invalid"),
        (_missing(refs=["src/app.py"]), "refs_invalid"),
        (_missing(refs=[_REF_A, _REF_A]), "refs_duplicate"),
        (
            _missing(
                refs=[
                    _REF_A,
                    _REF_B,
                    _REF_C,
                    "clm_20000000-0000-4000-8000-000000000009",
                    "evd_30000000-0000-4000-8000-000000000009",
                ]
            ),
            "refs_invalid",
        ),
        (_missing(reason=""), "text_bounds"),
        (_missing(reason="x" * 300), "text_bounds"),
    ],
)
def test_malformed_missing_items_carry_one_closed_stage(
    missing: dict[str, JsonValue], stage: str
) -> None:
    value = _judgment("insufficient_packet", missing=[missing])
    assert not _provider_schema_accepts(cast(JsonValue, value))
    with pytest.raises(JudgmentValidationError) as info:
        normalize_judgment(cast(JsonValue, value))
    assert info.value.stage == stage


def test_every_missing_kind_and_field_has_a_reviewer_gloss() -> None:
    definitions = cast(dict[str, Any], JUDGMENT_JSON_SCHEMA["$defs"])
    kinds = cast(dict[str, Any], definitions["MissingForAssessmentKindWire"])
    assert set(kinds["enum"]) == set(MISSING_ITEM_KIND_GLOSSARY)
    for kind in MISSING_ITEM_KIND_GLOSSARY:
        assert f"{kind}: " in kinds["description"]
    item = cast(dict[str, Any], definitions["ProviderMissingItem"])
    assert set(MISSING_ITEM_FIELD_GLOSSARY) == set(cast(dict[str, Any], item["properties"]))


def test_released_provider_judgment_1_0_stays_frozen_beside_1_1() -> None:
    released = cast(dict[str, Any], strict_json_parse(_RELEASED_1_0_SCHEMA.read_bytes()))
    insufficient = released["$defs"]["ProviderJudgmentInsufficient"]
    assert set(insufficient["properties"]) == {"conclusion", "reviewer_challenges"}
    current = cast(dict[str, Any], strict_json_parse(_FROZEN_SCHEMA.read_bytes()))
    assert "missing_for_assessment" in current["$defs"]["ProviderJudgmentInsufficient"]["required"]


def _ruling(**overrides: JsonValue) -> dict[str, JsonValue]:
    return {
        "finding_id": "fnd_866db2dd-0000-4000-8000-000000000001",
        "verdict": "fixed",
        "cited_refs": [_REF_C],
        "note": "The regression result recorded after the finding shows distinct keys.",
        **overrides,
    }


def test_a_reply_without_rulings_reads_as_the_1_0_0_shape_with_none() -> None:
    """A local model or prompt-only host may still answer without the array (issue #905).

    That is an explicit backward read: no rulings, so nothing can ever be ``fixed``; it must not
    fail the whole review and discard its challenges.
    """

    legacy = {"conclusion": "challenges_returned", "reviewer_challenges": [_challenge()]}
    for parsed in (legacy, {"judgment": legacy}):
        judgment = normalize_judgment(cast(JsonValue, parsed))
        assert len(judgment.challenges) == 1
        assert judgment.prior_finding_verdicts == ()
        assert judgment.prior_finding_verdicts_dropped == 0


def test_a_malformed_or_surplus_ruling_is_dropped_and_counted_not_fatal() -> None:
    malformed: list[JsonValue] = [
        _ruling(finding_id="fnd_866db2dd"),
        _ruling(verdict="resolved"),
        _ruling(note=""),
        "fixed",
    ]
    judgment = normalize_judgment(
        cast(
            JsonValue,
            {
                **_judgment("challenges_returned", [_challenge()]),
                "prior_finding_verdicts": [_ruling(), *malformed],
            },
        )
    )
    assert len(judgment.challenges) == 1
    assert [item.verdict for item in judgment.prior_finding_verdicts] == ["fixed"]
    assert judgment.prior_finding_verdicts_dropped == len(malformed)

    surplus = normalize_judgment(
        cast(
            JsonValue,
            {
                **_judgment(),
                "prior_finding_verdicts": [
                    _ruling(verdict="unassessable", finding_id=_finding(number))
                    for number in range(1, 10)
                ],
            },
        )
    )
    assert len(surplus.prior_finding_verdicts) == 8
    assert surplus.prior_finding_verdicts_dropped == 1


def _finding(number: int) -> str:
    return f"fnd_866db2dd-0000-4000-8000-{number:012d}"


def test_row_level_rulings_fold_to_one_per_finding_before_the_cap() -> None:
    """A reply with one ruling per prior-finding row must not strand a later finding (#905).

    Prose-bearing earlier findings carry several rows each. A provider that answers per row
    returns more rulings than the eight-entry cap while naming only three findings; the rulings
    are folded by ``finding_id`` first, so every finding keeps its ruling and each repeat is
    counted.
    """

    rows: list[JsonValue] = [
        *[_ruling(finding_id=_finding(3), verdict="still_present")] * 7,
        *[_ruling(finding_id=_finding(2), verdict="answered_not_fixed")] * 7,
        *[_ruling(finding_id=_finding(1), verdict="fixed")] * 3,
    ]
    judgment = normalize_judgment(cast(JsonValue, {**_judgment(), "prior_finding_verdicts": rows}))
    assert [(item.finding_id, item.verdict) for item in judgment.prior_finding_verdicts] == [
        (_finding(3), "still_present"),
        (_finding(2), "answered_not_fixed"),
        (_finding(1), "fixed"),
    ]
    assert judgment.prior_finding_verdicts_dropped == len(rows) - 3


def test_conflicting_rulings_on_one_finding_fold_to_unassessable() -> None:
    """Two different rulings on one finding settle nothing about it, and never become fixed."""

    judgment = normalize_judgment(
        cast(
            JsonValue,
            {
                **_judgment(),
                "prior_finding_verdicts": [
                    _ruling(finding_id=_finding(1), verdict="fixed"),
                    _ruling(finding_id=_finding(2), verdict="withdrawn", cited_refs=[]),
                    _ruling(finding_id=_finding(1), verdict="still_present"),
                ],
            },
        )
    )
    assert [
        (item.finding_id, item.verdict, item.cited_refs) for item in judgment.prior_finding_verdicts
    ] == [(_finding(1), "unassessable", ()), (_finding(2), "withdrawn", ())]
    assert judgment.prior_finding_verdicts_dropped == 1


def test_the_instruction_asks_for_exactly_one_ruling_per_listed_finding() -> None:
    """Every provider shares the text that names the rulable list and the per-finding rule."""

    from yoetz.adapters.providers.openai_responses import (
        SEMANTIC_REVIEW_INSTRUCTION,
        VERDICT_FIELD_GLOSSARY,
    )

    assert "review_packet.prior_finding_refs" in SEMANTIC_REVIEW_INSTRUCTION
    assert "exactly one prior_finding_verdicts entry" in SEMANTIC_REVIEW_INSTRUCTION
    assert "never one per row" in SEMANTIC_REVIEW_INSTRUCTION
    assert "review_packet.prior_finding_refs" in VERDICT_FIELD_GLOSSARY["finding_id"]


@pytest.mark.parametrize("value", [None, "fixed", {"finding_id": "fnd_866db2dd"}])
def test_a_present_non_array_rulings_value_is_counted_not_read_as_the_1_0_0_shape(
    value: JsonValue,
) -> None:
    """Only an absent key is the older shape; ``null`` or a non-array is a malformed reply."""

    judgment = normalize_judgment(
        cast(
            JsonValue,
            {**_judgment("challenges_returned", [_challenge()]), "prior_finding_verdicts": value},
        )
    )
    assert len(judgment.challenges) == 1
    assert judgment.prior_finding_verdicts == ()
    assert judgment.prior_finding_verdicts_dropped == 1


def test_verified_rows_inconsistent_with_their_verdict_cost_only_themselves() -> None:
    """Strict output cannot couple snippet to verdict; a mismatched row must not reject the review.

    A not_assessable row keeps its judgement without the quote; a supported/not_supported row
    without a quote is dropped and counted so the check can disclose it.
    """

    ref = "evt_00000000-0000-4000-8000-000000000001"
    body: dict[str, Any] = {
        "judgment": {
            "conclusion": "no_material_discrepancy",
            "review_summary": "Checked three rows.",
            "prior_finding_verdicts": [],
            "reviewer_challenges": [],
            "verified": [
                {
                    "requirement_or_claim": "Quoted support",
                    "verdict": "supported",
                    "cited_refs": [ref],
                    "snippet": "quoted",
                },
                {
                    "requirement_or_claim": "Support without a quote",
                    "verdict": "supported",
                    "cited_refs": [ref],
                    "snippet": None,
                },
                {
                    "requirement_or_claim": "Unassessable with a stray quote",
                    "verdict": "not_assessable",
                    "cited_refs": [ref],
                    "snippet": "stray",
                },
            ],
        }
    }
    judgment = normalize_judgment(cast(JsonValue, body), require_part2=True)
    assert judgment.verified_dropped == 1
    assert [(item.requirement_or_claim, item.snippet) for item in judgment.verified] == [
        ("Quoted support", "quoted"),
        ("Unassessable with a stray quote", None),
    ]
