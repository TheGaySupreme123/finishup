"""Foundation contract matrix for the frozen MCP surface."""

from __future__ import annotations

import re
from collections.abc import Callable
from copy import deepcopy
from typing import Any, cast

import pytest
from jsonschema import Draft202012Validator
from pydantic import BaseModel, ConfigDict, ValidationError

from builders.readiness import with_checklist
from yoetz.mcp import resources as resource_module
from yoetz.mcp.descriptors import (
    ADVERTISED_SURFACE_BUDGET,
    INITIALIZE_GUIDANCE_URIS,
    ORDINARY_MCP_PUBLISH_EVENT_FAMILIES,
    PRESENTATION_INPUT_SCHEMA_BUDGETS,
    SERVER_INSTRUCTIONS_BUDGET,
    TOOL_DESCRIPTOR_DIGESTS,
    TOOL_DESCRIPTOR_SET_DIGEST,
    TOOL_DESCRIPTORS,
    McpRouteProfile,
    advertised_surface_metrics,
    descriptor_for,
    ordinary_publish_families_in_presentation,
    presentation_schema_metrics,
    server_instructions,
)
from yoetz.mcp.errors import (
    build_last_resort_internal_error_result,
    build_public_error_result,
    safe_validation_locations,
    sanitize_unknown_tool_name,
)
from yoetz.mcp.resources import (
    GUIDANCE_RESOURCES,
    GuidanceResourceError,
    list_resources,
    read_resource,
)
from yoetz.mcp.semantic_destination import (
    DISCLOSURE_PREFIX,
    MAX_DISCLOSURE_ENCODED_BYTES,
    SemanticDestinationDisclosure,
)
from yoetz.mcp.summaries import render_safe_compact_summary
from yoetz.protocol.canonical import JsonValue
from yoetz.protocol.errors import SAFE_DETAIL_KEYS, PublicErrorCode
from yoetz.protocol.models import (
    FRONTIER_LEAVES,
    REGISTERED_GUIDANCE_URIS,
    PublishWorkRequest,
    StartRequest,
    StatusRequest,
)
from yoetz.protocol.schemas import (
    load_schema_catalog,
    request_result_schema_versions,
    validate_schema_instance,
)

_EXPECTED_TOOL_NAMES = (
    "start",
    "publish_work",
    "check",
    "respond",
    "status",
    "receipt",
    "read_guidance",
    "closure_prepare",
)
_WORKFLOW_TOOL_NAMES = (
    "start",
    "publish_work",
    "check",
    "respond",
    "status",
    "receipt",
)
_EXPECTED_RESOURCE_URIS = (
    "yoetz://guidance/agent-instructions.md",
    "yoetz://guidance/workflow.md",
    "yoetz://guidance/publication-policy.md",
    "yoetz://guidance/coverage-and-receipts.md",
    "yoetz://guidance/request-templates.md",
)
_FORBIDDEN_DESCRIPTOR_CLAIMS = re.compile(
    r"\b(?:authenticated|enforces?|gates?|observes?|proved|proves?|verified)\b",
    re.IGNORECASE | re.ASCII,
)


def test_fallback_error_object_is_admitted() -> None:
    fallback = build_last_resort_internal_error_result()

    for operation in _WORKFLOW_TOOL_NAMES:
        validate_schema_instance(f"{operation.replace('_', '-')}-result", "1.0.0", fallback)
    validate_schema_instance("read-guidance-result", "1.0.0", fallback)
    validate_schema_instance("closure-prepare-result", "1.0.0", fallback)


def test_public_error_and_validation_summaries_are_sanitized() -> None:
    correlation_id = "err_00000000-0000-4000-8000-000000000001"
    result = build_public_error_result(
        PublicErrorCode.INVALID_REQUEST,
        "The request is invalid.",
        False,
        correlation_id,
        safe_details={"field": "/request_id"},
    )
    assert result == {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "ok": False,
        "error": {
            "code": "INVALID_REQUEST",
            "message": "The request is invalid.",
            "retryable": False,
            "correlation_id": correlation_id,
            "safe_details": {"field": "/request_id"},
        },
    }
    summary = render_safe_compact_summary(result)
    assert summary == (
        f"Error INVALID_REQUEST; retryable: no; correlation: {correlation_id}. Field: /request_id."
    )
    all_locations = (
        {"field": "/request_id", "reason": "missing"},
        {"field": "/client", "reason": "extra_forbidden"},
    )
    multi_location_result = build_public_error_result(
        PublicErrorCode.INVALID_REQUEST,
        "The request is invalid.",
        False,
        correlation_id,
        safe_details=all_locations,
    )
    multi_location_error = cast(dict[str, object], multi_location_result["error"])
    assert multi_location_error["safe_details"] == {
        "continuation": "input_correction_new_identity",
        "fields": ["/request_id", "/client"],
        "reasons": ["missing", "extra_forbidden"],
    }
    multi_location_summary = render_safe_compact_summary(multi_location_result)
    assert "Rejected: missing at /request_id; extra_forbidden at /client." in multi_location_summary
    assert "Continuation: input_correction_new_identity." in multi_location_summary

    class _Request(BaseModel):
        model_config = ConfigDict(extra="forbid")

        request_id: str

    with pytest.raises(ValidationError) as captured:
        _Request.model_validate({"password": "never-echo-this"})
    locations = safe_validation_locations(captured.value)
    assert locations == ({"field": "/request_id", "reason": "missing"},)
    assert "password" not in repr(locations)
    assert "never-echo-this" not in repr(locations)


def test_forbidden_client_id_projects_parent_path_in_safe_details() -> None:
    class _ClientInfo(BaseModel):
        model_config = ConfigDict(extra="forbid")

        kind: str
        version: str
        integration: str

    class _Request(BaseModel):
        model_config = ConfigDict(extra="forbid")

        client: _ClientInfo

    with pytest.raises(ValidationError) as captured:
        _Request.model_validate(
            {
                "client": {
                    "kind": "cooperative_agent",
                    "version": "0.1.0",
                    "integration": "cooperative_mcp",
                    "id": "invented-client-id",
                }
            }
        )
    locations = safe_validation_locations(captured.value)
    assert locations == ({"field": "/client", "reason": "extra_forbidden"},)
    assert "/client/id" not in repr(locations)
    assert "invented-client-id" not in repr(locations)
    # "id" must not be a generally trusted location segment.
    assert '"id"' not in repr(locations)


def test_frontier_leaf_names_are_locatable_in_safe_details() -> None:
    """A wrong frontier key must name the missing leaf, not just the object holding it.

    The 2026-07-26 dogfood sent ``digest`` instead of ``head_digest``; the whole diagnostic was
    "/expected_frontier missing", which does not say what to write. Frontier leaves are frozen
    schema names already trusted as ``SAFE_DETAIL_KEYS``, so they are safe to locate.
    """

    assert set(FRONTIER_LEAVES) <= set(SAFE_DETAIL_KEYS)

    examples = descriptor_for("publish_work").input_schema["examples"]
    assert isinstance(examples, list)
    base = examples[0]
    assert isinstance(base, dict)

    with pytest.raises(ValidationError) as captured:
        PublishWorkRequest.model_validate(
            {**base, "expected_frontier": {"sequence": "10", "digest": f"sha256:{'a' * 64}"}}
        )
    locations = safe_validation_locations(captured.value)

    assert {"field": "/expected_frontier/head_digest", "reason": "missing"} in locations
    # The caller-supplied extra key is still projected to its parent and never named.
    assert {"field": "/expected_frontier", "reason": "extra_forbidden"} in locations
    assert not any(item["field"].endswith("/digest") for item in locations)


def test_rejected_event_draft_is_located_by_ordinal() -> None:
    """A bad draft in a batch must be identified by its ordinal, never by echoing its content."""

    examples = descriptor_for("publish_work").input_schema["examples"]
    assert isinstance(examples, list)
    base = cast(dict[str, object], examples[0])
    good = cast(list[object], base["event_drafts"])[0]
    assert isinstance(good, dict)
    secret = "NOT-A-REAL-ENUM-never-echo-this"
    bad: dict[str, object] = {
        **good,
        "event_id": "evt_00000000-0000-4000-8000-000000000099",
        "schema": {"name": "action_recorded", "version": "1.0.0"},
        "payload": {
            "action_id": "act_00000000-0000-4000-8000-000000000098",
            "action_kind": secret,
            "description": "x",
        },
    }

    with pytest.raises(ValidationError) as captured:
        PublishWorkRequest.model_validate({**base, "event_drafts": [good, bad]})
    locations = safe_validation_locations(captured.value)

    assert any(item["field"] == "/event_drafts/1/payload/action_kind" for item in locations)
    assert secret not in repr(locations)
    from yoetz.mcp.errors import authoring_hint

    hint = authoring_hint(descriptor_for("publish_work").input_schema, locations)
    assert "action_kind admits" in hint
    assert secret not in hint


def test_unknown_nested_payload_key_keeps_the_extra_forbidden_reason() -> None:
    """Both producers of `extra_forbidden` are pinned here: the envelope model and jsonschema.

    Top-level extras come from `_ClosedModel`'s `extra="forbid"`; a key inside an event payload is
    admitted only by the frozen event schema, and its verdict reaches this projection through
    `SchemaInstanceInvalid` (issue #240).
    """

    examples = descriptor_for("publish_work").input_schema["examples"]
    assert isinstance(examples, list)
    base = cast(dict[str, object], examples[0])
    good = cast(dict[str, object], cast(list[object], base["event_drafts"])[0])
    secret = "never_echo_this_unknown_payload_key"
    payload = {**cast(dict[str, object], good["payload"]), secret: "x"}

    with pytest.raises(ValidationError) as captured:
        PublishWorkRequest.model_validate({**base, "event_drafts": [{**good, "payload": payload}]})
    locations = safe_validation_locations(captured.value)

    assert {"field": "/event_drafts/0/payload", "reason": "extra_forbidden"}.items() <= (
        locations[0].items()
    )
    assert secret not in repr(locations)
    # Only the two wire keys are projected; the family and count stay inside the process.
    wire = build_public_error_result(
        PublicErrorCode.INVALID_REQUEST,
        "The request is invalid.",
        False,
        "err_00000000-0000-4000-8000-000000000002",
        safe_details=locations,
    )
    details = cast(dict[str, object], cast(dict[str, object], wire["error"])["safe_details"])
    assert details == {
        "continuation": "input_correction_new_identity",
        "fields": ["/event_drafts/0/payload"],
        "reasons": ["extra_forbidden"],
    }


def test_unknown_tool_message_is_sanitized() -> None:
    raw_name = "../../private/secret-tool"
    message = sanitize_unknown_tool_name(raw_name)

    assert message == "The requested tool is not registered."
    assert raw_name not in message


def test_descriptor_text_is_frozen_and_honest() -> None:
    assert tuple(TOOL_DESCRIPTORS) == ("policy", "strict")
    assert tuple(TOOL_DESCRIPTOR_DIGESTS) == ("policy", "strict")
    assert TOOL_DESCRIPTOR_SET_DIGEST == {
        "policy": "sha256:bbb25999ea58f9f275c1eacd1a20b4793098c49a8892b067f29f74a79932f997",
        "strict": "sha256:61fc5da787955d9278413533e155601274edae098cee996141a7d701a30688d6",
    }
    for profile, descriptors in TOOL_DESCRIPTORS.items():
        assert tuple(item.name for item in descriptors) == _EXPECTED_TOOL_NAMES
        assert tuple(TOOL_DESCRIPTOR_DIGESTS[profile]) == _EXPECTED_TOOL_NAMES
    for name in _EXPECTED_TOOL_NAMES:
        assert "yoetz://guidance/" in descriptor_for(name).description
    # The check descriptor carries the full mode decision rule, including semantic_required.
    check_description = descriptor_for("check").description
    assert "semantic_if_configured only when review is known to be optional" in check_description
    assert "semantic_required when the user, effective policy or acceptance requires it" in (
        check_description
    )
    assert "Omit mode to preserve the configured default" in check_description
    respond_description = descriptor_for("respond").description
    # Issue #911: any in-chain frontier at or after the record is accepted, so the descriptor
    # never implies the exact check result frontier that sent agents hunting through history.
    assert "any frontier at or after its record" in respond_description
    assert "current status frontier" in respond_description
    assert "result frontier of the check that returned it" not in respond_description
    assert "not its subject_frontier" in respond_description
    for local_description in (descriptor_for("publish_work").description, respond_description):
        assert "local Yoetz ledger" in local_description
        assert "does not publish to GitHub" in local_description
        assert "run an AI-powered evaluation" in local_description
    assert descriptor_for("start").description.startswith(
        "First read yoetz://guidance/agent-instructions.md."
    )
    # The two argument conventions a first-time caller cannot infer from prose alone. Both cost a
    # rejected start call in the 2026-07-30 dogfood before the descriptor named them.
    start_description = descriptor_for("start").description
    assert "fresh req_ prefixed random UUID" in start_description
    assert "workspace_ref and external_ref are admitted only as a pair" in start_description
    assert "A new session's first workflow operation is this call" in start_description
    assert "for intro and guidance" in start_description
    assert (
        "unique and already in ascending ASCII order" in descriptor_for("publish_work").description
    )
    assert "unsorted_set_field" in descriptor_for("publish_work").description
    properties = descriptor_for("publish_work").input_schema["properties"]
    assert isinstance(properties, dict)
    event_drafts = properties["event_drafts"]
    assert isinstance(event_drafts, dict)
    description = event_drafts["description"]
    assert isinstance(description, str)
    assert "unsorted_set_field" in description
    publish_descriptor = descriptor_for("publish_work")
    assert publish_descriptor.input_schema_ref.endswith("publish-work-request-1.2.0.schema.json")
    assert publish_descriptor.output_schema_ref.endswith("publish-work-result-1.1.0.schema.json")
    check_descriptor = descriptor_for("check")
    assert check_descriptor.output_schema_ref.endswith("check-result-1.4.0.schema.json")
    status_descriptor = descriptor_for("status")
    assert status_descriptor.input_schema_ref.endswith("status-request-1.2.0.schema.json")
    assert status_descriptor.output_schema_ref.endswith("status-result-1.4.0.schema.json")
    receipt_descriptor = descriptor_for("receipt")
    assert receipt_descriptor.output_schema_ref.endswith("receipt-result-1.3.0.schema.json")
    closure_descriptor = descriptor_for("closure_prepare")
    assert closure_descriptor.input_schema_ref.endswith("closure-prepare-request-1.0.0.schema.json")
    assert closure_descriptor.output_schema_ref.endswith("closure-prepare-result-1.0.0.schema.json")
    assert "never writes the ledger, judges work, or claims completion" in (
        closure_descriptor.description
    )
    for descriptors in TOOL_DESCRIPTORS.values():
        assert {item.name for item in descriptors if item.annotations.read_only} == {
            "status",
            "read_guidance",
            "closure_prepare",
        }
        assert all(not item.annotations.destructive for item in descriptors)
        assert all(item.annotations.idempotent for item in descriptors)
        assert all(
            _FORBIDDEN_DESCRIPTOR_CLAIMS.search(item.description) is None for item in descriptors
        )
    assert descriptor_for("check", "policy").annotations.open_world is True
    assert descriptor_for("check", "strict").annotations.open_world is False
    assert (
        "this route will not request external AI-powered review"
        in descriptor_for("check", "strict").description
    )
    for name in set(_EXPECTED_TOOL_NAMES) - {"check"}:
        assert descriptor_for(name, "policy") == descriptor_for(name, "strict")
    assert "uncertain what you already did or committed to" in descriptor_for("status").description
    assert "recommended_next_action" in descriptor_for("status").description
    assert "caller-asserted occurred_at beside the service-stamped accepted_at" in (
        descriptor_for("status").description
    )
    assert "call receipt before claiming completion" in descriptor_for("publish_work").description
    assert "do not copy the illustrative example timestamp" in (
        descriptor_for("publish_work").description
    )
    assert "Service accepted_at" in descriptor_for("publish_work").description
    assert "frontier-bound" in descriptor_for("publish_work").description
    assert "ingestion sequence" in descriptor_for("publish_work").description
    base_instructions = read_resource("yoetz://guidance/agent-instructions.md").decode("utf-8")
    workflow = read_resource("yoetz://guidance/workflow.md").decode("utf-8")
    coverage = read_resource("yoetz://guidance/coverage-and-receipts.md").decode("utf-8")
    assert INITIALIZE_GUIDANCE_URIS == ("yoetz://guidance/agent-instructions.md",)
    assert server_instructions().startswith(base_instructions.rstrip())
    assert server_instructions() == f"{base_instructions.rstrip()}\n\nRoute profile: policy. " + (
        "External AI-powered review follows the configured policy.\n"
    )
    # Inlining these two cost 24 KB on every advertised tool description (#300). They are fetched
    # on demand instead; the catalog paragraph below is what makes that reachable.
    assert workflow.rstrip() not in server_instructions()
    assert coverage.rstrip() not in server_instructions()
    assert "Route profile: policy." in server_instructions()
    assert "Do not call `resources/list` or `list_mcp_resources` to find Yoetz guidance" in (
        server_instructions()
    )
    # The on-demand catalog is only reachable because the inlined document names both the URI set
    # and the read_guidance recovery path. Losing either line strands the un-inlined documents.
    assert "yoetz://guidance/workflow.md" in server_instructions()
    assert "yoetz://guidance/coverage-and-receipts.md" in server_instructions()
    assert "call `read_guidance` with the same URI" in server_instructions()
    strict_instructions = server_instructions("strict")
    assert "Route profile: strict." in strict_instructions
    assert "This route will not request external AI-powered review" in strict_instructions
    # #479: the bridge appends the startup-read AI-powered destination disclosure to the policy
    # tail only; the strict tail is byte-identical with or without one, and the packaged text
    # never carries the passage on its own.
    disclosure = SemanticDestinationDisclosure("unknown", DISCLOSURE_PREFIX + "unknown.")
    assert server_instructions("policy", semantic_destination=disclosure) == (
        f"{base_instructions.rstrip()}\n\nRoute profile: policy. "
        "External AI-powered review follows the configured policy. "
        f"{disclosure.sentence}\n"
    )
    assert server_instructions("strict", semantic_destination=disclosure) == strict_instructions
    assert DISCLOSURE_PREFIX not in server_instructions()
    assert DISCLOSURE_PREFIX not in strict_instructions

    with pytest.raises(KeyError, match="unregistered_tool_descriptor") as captured:
        descriptor_for("secret-tool")
    assert "secret-tool" not in str(captured.value)


def test_advertised_schema_versions_match_catalog_current_versions() -> None:
    """Every tools/list schema reference must point at the catalog's current result contract."""

    catalog = load_schema_catalog()
    current_versions = request_result_schema_versions(catalog)
    for profile in TOOL_DESCRIPTORS:
        for descriptor in TOOL_DESCRIPTORS[profile]:
            for kind, reference in (
                ("request", descriptor.input_schema_ref),
                ("result", descriptor.output_schema_ref),
            ):
                schema_name = f"{descriptor.name.replace('_', '-')}-{kind}"
                expected_version = current_versions[schema_name]
                assert reference.endswith(f"{schema_name}-{expected_version}.schema.json"), (
                    f"{profile}/{descriptor.name} advertises a stale {kind} schema"
                )


_SUBSCRIPTION_DIGEST = "sha256:" + "a" * 64
_SUBSCRIPTION_COMMITMENT = "hmac-sha256:" + "b" * 64


def _subscription_id(prefix: str, ordinal: int) -> str:
    return f"{prefix}00000000-0000-4000-8000-{ordinal:012d}"


def _subscription_coverage() -> dict[str, Any]:
    return {
        "publication_channels": ["cooperative_mcp"],
        "authorship_assurance": "service_authenticated",
        "artifact_observation": "published_only",
        "evidence_immutability": "metadata_only",
        "ledger_freshness": "current",
        "check_types": ["deterministic", "semantic_model_derived"],
        "known_gaps": [],
    }


def _subscription_privacy_projection() -> dict[str, Any]:
    return {
        "sink": "agent_context",
        "local_disclosure_receipt_id": _subscription_id("egr_", 2),
        "policy_id": _subscription_id("pvy_", 3),
        "policy_version": "1",
        "policy_digest": _SUBSCRIPTION_DIGEST,
        "included_categories": [],
        "blocked_categories": [],
        "omitted_pointers": [],
        "projection_commitment": _SUBSCRIPTION_COMMITMENT,
    }


def _subscription_provenance() -> dict[str, Any]:
    return {
        "provider": "openai-codex",
        "endpoint_profile_id": "codex-chatgpt-subscription",
        "endpoint_profile_version": "1.0.0",
        "model": "gpt-5.6-luna",
        "sdk_version": "codex-app-server-0.150.1",
        "prompt_digest": _SUBSCRIPTION_DIGEST,
        "schema_digest": _SUBSCRIPTION_DIGEST,
        "policy_digest": _SUBSCRIPTION_DIGEST,
        "privacy_policy_digest": _SUBSCRIPTION_DIGEST,
        "sampling_params": {"max_output_tokens": "2048"},
        "latency_ms": "321",
        "semantic_attempt_id": _subscription_id("att_", 1),
        "dispatch_kind": "external_runtime_oauth",
        "privacy_receipt_id": _subscription_id("egr_", 2),
        "token_usage": {
            "input_tokens": "103",
            "output_tokens": "19",
            "total_tokens": "122",
        },
        "status": "succeeded",
        "reason": "semantic_completed",
        "egress_authorization_id": _subscription_id("aut_", 3),
        "request_commitment": _SUBSCRIPTION_COMMITMENT,
        "runtime_evidence": {
            "app_server_schema_sha256": _SUBSCRIPTION_DIGEST,
            "capability_cell_sha256": _SUBSCRIPTION_DIGEST,
            "capability_evidence_expires_at": "2026-11-30T00:00:00Z",
            "capability_profile": "codex-evaluator/0.150.1/v1",
            "case_disclosed": True,
            "credential_authority": "external_runtime_oauth",
            "disclosed_case_sha256": _SUBSCRIPTION_DIGEST,
            "executable_sha256": _SUBSCRIPTION_DIGEST,
            "instruction_sha256": _SUBSCRIPTION_DIGEST,
            "isolated_config_sha256": _SUBSCRIPTION_DIGEST,
            "launcher_sha256": _SUBSCRIPTION_DIGEST,
            "output_schema_sha256": _SUBSCRIPTION_DIGEST,
            "process_cleanup": "terminated",
            "reasoning_effort": "high",
            "runtime_source_identity": "openai-codex-npm-darwin-arm64-0.150.1",
            "runtime_version": "0.150.1",
            "selection_sha256": _SUBSCRIPTION_DIGEST,
            "turn_acknowledged": True,
            "upstream_body_observability": "unavailable",
            "auth_mode": "chatgpt",
            "plan_type": "prolite",
            "thread_id": "thread-1",
            "turn_id": "turn-1",
            "final_output_sha256": _SUBSCRIPTION_DIGEST,
            "token_usage": {
                "cached_input_tokens": "101",
                "cache_write_input_tokens": "17",
                "input_tokens": "103",
                "output_tokens": "19",
                "reasoning_output_tokens": "11",
                "total_tokens": "122",
            },
        },
    }


def _subscription_finding() -> dict[str, Any]:
    return {
        "finding_id": _subscription_id("fnd_", 8),
        "kind": "material_limitation_omitted",
        "origin": "semantic_model_derived",
        "priority": 1,
        "summary": "The synthetic AI-powered finding remains advisory.",
        "detail": "The synthetic AI-powered finding remains advisory.",
        "subject_refs": [_subscription_id("clm_", 9)],
        "policy_id": "research-evidence",
        "policy_version": "0.1.0",
        "subject_frontier": {"sequence": "1", "head_digest": _SUBSCRIPTION_DIGEST},
        "coverage": _subscription_coverage(),
        "provenance": _subscription_provenance(),
    }


def _subscription_check_result() -> dict[str, Any]:
    frontier = {"sequence": "1", "head_digest": _SUBSCRIPTION_DIGEST}
    return {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": _subscription_id("req_", 7),
        "ok": True,
        "state": "complete",
        "task_id": _subscription_id("tsk_", 4),
        "session_id": _subscription_id("ses_", 5),
        "writer_id": _subscription_id("wri_", 6),
        "subject_frontier": frontier,
        "result_frontier": frontier,
        "verdict": "action_required",
        "findings": [_subscription_finding()],
        "suppressed_count": "0",
        "policy_executions": [
            {
                "policy_id": "work-integrity",
                "policy_version": "0.1.0",
                "outcome": "run",
                "reason": "completed",
            }
        ],
        "semantic_status": "succeeded",
        "semantic_reason": "semantic_completed",
        "semantic_provenance": _subscription_provenance(),
        "coverage": _subscription_coverage(),
        "versions": {
            "protocol_version": "0.1",
            "engine_version": "0.1.0",
            "projection_version": "0.1.0",
            "policy_packs": ["work-integrity/0.3.0"],
        },
        "privacy_projection": _subscription_privacy_projection(),
    }


def _subscription_status_result() -> dict[str, Any]:
    frontier = {"sequence": "1", "head_digest": _SUBSCRIPTION_DIGEST}
    finding = _subscription_finding()
    finding.update(
        {
            "disposition": "none",
            "resolved": False,
            "response_event_id": None,
            "reason": None,
            "waiver_scope": None,
            "waiver_expiry": None,
        }
    )
    return {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": _subscription_id("req_", 10),
        "ok": True,
        "task_id": _subscription_id("tsk_", 4),
        "session_id": _subscription_id("ses_", 5),
        "writer_id": _subscription_id("wri_", 6),
        "view": "findings",
        "requested_frontier": frontier,
        "head_frontier": frontier,
        "subject_frontier": frontier,
        "result_frontier": frontier,
        "projection_lag": "0",
        "projection_version": "0.1.0",
        "rebuild_state": "current",
        "page": {"items": [finding], "next_cursor": None},
        "coverage": _subscription_coverage(),
        "gaps": [],
        "import_status": {
            "pending_count": "0",
            "terminal_count": "0",
            "phase": None,
            "report_evidence_id": None,
            "source_identity_digest": None,
        },
        "closure_readiness": with_checklist(
            {
                "declared_obligation_count": "0",
                "no_obligations_reason": None,
                "open_obligation_count": "0",
                "unanswered_finding_count": "1",
                "receipt_blocking_finding_count": "1",
                "blocking_conditions": ["findings_unanswered"],
            }
        ),
        "privacy_projection": _subscription_privacy_projection(),
    }


def _subscription_receipt_result() -> dict[str, Any]:
    frontier = {"sequence": "1", "head_digest": _SUBSCRIPTION_DIGEST}
    finding = _subscription_finding()
    document: dict[str, Any] = {
        "schema_version": "1.0.0",
        "receipt_id": _subscription_id("rcp_", 11),
        "task_id": _subscription_id("tsk_", 4),
        "session_id": _subscription_id("ses_", 5),
        "generated_at": "2026-09-05T00:00:00.000Z",
        "subject_frontier": frontier,
        "conclusion": "unresolved_findings_remain",
        "suppressed_finding_count": 0,
        "versions": {
            "package_name": "yoetz",
            "package_version": "0.1.0",
            "protocol_version": "0.1",
            "engine_version": "0.1.0",
            "projection_version": "yoetz/0.1.0",
            "object_format_version": "yoetz-object/1",
            "catalog_schema_version": "6",
            "bundle_schema_version": "9",
            "policy_versions": [
                {"policy_id": "research-evidence", "policy_version": "0.1.0"},
                {"policy_id": "work-integrity", "policy_version": "0.1.0"},
            ],
            "schema_versions": [
                {"schema_id": "findings/finding", "schema_version": "1.3.0"},
                {"schema_id": "receipts/receipt-document", "schema_version": "1.3.0"},
            ],
            "resource_manifest_digest": _SUBSCRIPTION_DIGEST,
        },
        "coverage": _subscription_coverage(),
        "findings": [finding],
        "obligations": [],
        "responses": [],
        "claim_refs": [_subscription_id("clm_", 9)],
        "evidence_refs": [],
        "gaps": [],
        "redactions": [],
        "children": {"children": []},
        "sections": [
            {"key": "summary", "title": "Summary", "body": "Synthetic receipt.", "items": []},
            {
                "key": "outstanding_work",
                "title": "Outstanding work",
                "body": "The synthetic finding remains open.",
                "items": [],
            },
            {
                "key": "findings_and_dispositions",
                "title": "Findings",
                "body": "One synthetic finding remains.",
                "items": [_subscription_id("fnd_", 8)],
            },
            {
                "key": "evidence_and_claim_basis",
                "title": "Evidence basis",
                "body": "The synthetic receipt carries bounded provenance.",
                "items": [],
            },
            {
                "key": "limitations_and_coverage",
                "title": "Limitations",
                "body": "The result is advisory.",
                "items": [],
            },
            {
                "key": "version_and_policy_identity",
                "title": "Versions and policy",
                "body": "Synthetic contract fixture.",
                "items": [],
            },
        ],
        "semantic_provenance": _subscription_provenance(),
    }
    return {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": _subscription_id("req_", 12),
        "ok": True,
        "receipt_id": document["receipt_id"],
        "task_id": document["task_id"],
        "session_id": document["session_id"],
        "subject_frontier": document["subject_frontier"],
        "result_frontier": {"sequence": "2", "head_digest": _SUBSCRIPTION_DIGEST},
        "receipt_object_id": _subscription_id("obj_", 13),
        "receipt_digest": _SUBSCRIPTION_DIGEST,
        "conclusion": document["conclusion"],
        "redaction_profile": "full_local",
        "format": "json",
        "include": "full",
        "document": document,
        "human_text": None,
        "coverage": document["coverage"],
        "suppressed_finding_count": document["suppressed_finding_count"],
        "versions": document["versions"],
        "privacy_projection": _subscription_privacy_projection(),
    }


@pytest.mark.parametrize("profile", ("policy", "strict"))
def test_advertised_outputs_accept_subscription_runtime_provenance(
    profile: McpRouteProfile,
) -> None:
    """Current MCP result declarations must carry the OAuth runtime provenance contract."""

    outputs = {
        "check": _subscription_check_result(),
        "status": _subscription_status_result(),
        "receipt": _subscription_receipt_result(),
    }
    for tool_name, output in outputs.items():
        validator = cast(
            Any, Draft202012Validator(cast(Any, descriptor_for(tool_name, profile).output_schema))
        )
        errors = sorted(validator.iter_errors(output), key=lambda error: list(error.path))
        assert not errors, f"{profile}/{tool_name}: {errors[0].json_path}: {errors[0].message}"


def test_respond_agent_surface_names_every_admitted_disposition() -> None:
    """The advertised respond text is the only place an MCP caller learns the per-disposition
    field rules: ``_mcp_presentation_schema`` drops respond-request's ``allOf`` before advertising
    it. A disposition added to the enum without a rule here is an undiscoverable wire value."""

    descriptor = descriptor_for("respond")
    schema = cast(dict[str, Any], dict(descriptor.input_schema))
    disposition = cast(dict[str, Any], cast(dict[str, Any], schema["properties"])["disposition"])
    admitted = tuple(cast(list[str], disposition["enum"]))
    assert admitted == (
        "acknowledged",
        "acknowledged_not_done",
        "duplicate_of",
        "provenance_disputed",
        "rejected",
        "reopened",
        "self_verified",
        "waived",
    )
    assert "allOf" not in schema
    rules = cast(str, disposition["description"]).lower()
    for value in admitted:
        assert value in rules, f"{value} has no advertised field rule"
    assert "requires reason" in rules
    # The tool description is the first text a caller reads, and it is digest-pinned.
    assert "provenance dispute" in descriptor.description
    assert "provenance_disputed" in descriptor.description
    # Issue #984: repair first, self-verify a Yoetz limit, acknowledge only as the last resort.
    text = descriptor.description
    assert text.index("repair it and check first") < text.index("respond self_verified")
    assert text.index("respond self_verified") < text.index("acknowledged_not_done only if")
    assert "never a yoetz-blocker" in text
    # Issue #996: the link target is advertised with its rule, and the text says what it does.
    target = cast(
        dict[str, Any], cast(dict[str, Any], schema["properties"])["duplicate_of_finding_id"]
    )
    assert "earlier" in cast(str, target["description"])
    assert "duplicate_of_finding_id" in rules
    assert "respond duplicate_of" in text
    assert "linking never resolves the new finding" in text


def test_guidance_resources_are_exact_and_static() -> None:
    assert tuple(item.uri for item in GUIDANCE_RESOURCES) == _EXPECTED_RESOURCE_URIS
    assert list_resources() is GUIDANCE_RESOURCES
    for item in GUIDANCE_RESOURCES:
        assert item.bytes == read_resource(item.uri)
        assert item.text.encode("utf-8") == item.bytes
        assert item.size == len(item.bytes)
        assert item.media_type == "text/markdown"
        assert item.annotations.audience == ("assistant",)
        assert 0.0 <= item.annotations.priority <= 1.0
        assert "Read " in item.description or item.description.startswith("Read")
    assert GUIDANCE_RESOURCES[0].annotations.priority == 1.0
    assert GUIDANCE_RESOURCES[1].annotations.priority == 0.9
    assert all(item.annotations.priority <= 0.9 for item in GUIDANCE_RESOURCES[1:])
    assert GUIDANCE_RESOURCES[2].annotations.priority == GUIDANCE_RESOURCES[3].annotations.priority
    assert GUIDANCE_RESOURCES[4].annotations.priority <= 0.9


def test_resource_uri_is_a_key_not_a_path(monkeypatch: pytest.MonkeyPatch) -> None:
    reads: list[str] = []

    def _unexpected_read(logical_name: str) -> bytes:
        reads.append(logical_name)
        raise AssertionError("package reader reached")

    monkeypatch.setattr(resource_module, "read_verified_resource", _unexpected_read)
    invalid_uris = (
        "guidance/workflow.md",
        "yoetz://guidance/{name}.md",
        "yoetz://guidance/../workflow.md",
        "yoetz://guidance//workflow.md",
        "file:///guidance/workflow.md",
    )
    for uri in invalid_uris:
        with pytest.raises(GuidanceResourceError, match="guidance_resource_uri_unregistered"):
            read_resource(uri)
    assert reads == []


@pytest.mark.parametrize("profile", ("policy", "strict"))
@pytest.mark.parametrize("family", ("plan_published", "plan_revised"))
def test_mcp_can_amend_review_input_without_replacing_the_session(
    profile: McpRouteProfile, family: str
) -> None:
    descriptor = descriptor_for("publish_work", profile)
    examples = cast(list[dict[str, Any]], descriptor.input_schema["examples"])
    request = deepcopy(
        next(
            example
            for example in examples
            if any(draft["schema"]["name"] == family for draft in example["event_drafts"])
        )
    )
    draft = next(item for item in request["event_drafts"] if item["schema"]["name"] == family)
    draft["schema"]["version"] = "1.1.0"
    draft["payload"]["task_statement"] = "Preserve the complete user request in this session."
    validator = Draft202012Validator(cast(Any, descriptor.input_schema))
    is_valid = cast(Callable[[Any], bool], getattr(validator, "is_valid"))
    assert is_valid(request)
    PublishWorkRequest.model_validate(request)
    validate_schema_instance(family.replace("_", "-"), "1.1.0", draft["payload"])

    # The new field must not accidentally become authorable under the frozen old wire version.
    draft["schema"]["version"] = "1.0.0"
    assert not is_valid(request)


def test_advertised_input_schemas_honor_presentation_keyword_budgets() -> None:
    for descriptor in TOOL_DESCRIPTORS["policy"]:
        schema_name = f"{descriptor.name.replace('_', '-')}-request"
        metrics = presentation_schema_metrics(descriptor.input_schema)
        budget = PRESENTATION_INPUT_SCHEMA_BUDGETS[schema_name]
        assert metrics["oneof_nodes"] <= budget["max_oneof_nodes"]
        assert metrics["oneof_branches"] <= budget["max_oneof_branches"]
        assert metrics["ref_nodes"] <= budget["max_ref_nodes"]
        assert metrics["conditional_nodes"] <= budget["max_conditional_nodes"]
        assert metrics["defs_count"] <= budget["max_defs_count"]
        assert metrics["defs_nest_depth"] <= budget["max_defs_nest_depth"]
        assert metrics["encoded_bytes"] <= budget["max_encoded_bytes"]
        encoded = repr(dict(descriptor.input_schema))
        assert "common/client-info" not in encoded
        assert "common/actor-assertion" not in encoded
        assert "common/frontier" not in encoded


def test_advertised_surface_honors_instructions_and_aggregate_budgets() -> None:
    """#300: the instructions block grew to 41 KB unnoticed because nothing bounded it, while the
    adjacent input schemas have been bounded since #128. A host may charge `instructions` once per
    advertised tool, so an unbounded edit here is multiplied, not merely added."""

    profiles: tuple[McpRouteProfile, ...] = ("policy", "strict")
    # #479: the policy route appends a runtime-composed destination disclosure of at most
    # MAX_DISCLOSURE_ENCODED_BYTES. The packaged text is held to the original bound on its own,
    # and the longest admissible disclosure is charged against the widened bound.
    longest = SemanticDestinationDisclosure(
        "external",
        DISCLOSURE_PREFIX + "x" * (MAX_DISCLOSURE_ENCODED_BYTES - len(DISCLOSURE_PREFIX)),
    )
    assert len(longest.sentence.encode("utf-8")) == MAX_DISCLOSURE_ENCODED_BYTES
    for profile in profiles:
        metrics = advertised_surface_metrics(profile)
        assert metrics["tool_count"] == len(_EXPECTED_TOOL_NAMES)
        assert (
            metrics["instructions_encoded_bytes"]
            <= (SERVER_INSTRUCTIONS_BUDGET["packaged_max_encoded_bytes"])
        ), f"{profile} packaged initialize instructions exceed their reviewed budget"
        assert (
            metrics["replicated_encoded_bytes"]
            <= (ADVERTISED_SURFACE_BUDGET["packaged_max_encoded_bytes"])
        ), f"{profile} packaged advertised surface exceeds its reviewed budget"
        metrics = advertised_surface_metrics(profile, semantic_destination=longest)
        assert (
            metrics["instructions_encoded_bytes"] <= SERVER_INSTRUCTIONS_BUDGET["max_encoded_bytes"]
        ), f"{profile} initialize instructions exceed their reviewed budget"
        assert (
            metrics["replicated_encoded_bytes"] <= ADVERTISED_SURFACE_BUDGET["max_encoded_bytes"]
        ), f"{profile} advertised surface exceeds its reviewed budget"
        # The aggregate must actually be an aggregate: a per-item bound cannot catch total growth.
        assert metrics["replicated_encoded_bytes"] == (
            metrics["instructions_encoded_bytes"] * metrics["tool_count"]
            + metrics["description_encoded_bytes"]
            + metrics["schema_encoded_bytes"]
        )
    # Guard the reason the aggregate budget is small enough to bite: exactly one inlined document.
    assert len(INITIALIZE_GUIDANCE_URIS) == 1


def test_publish_work_presentation_matches_ordinary_admission_families() -> None:
    schema = descriptor_for("publish_work").input_schema
    advertised = ordinary_publish_families_in_presentation(schema)
    assert advertised == ORDINARY_MCP_PUBLISH_EVENT_FAMILIES
    event_drafts = cast(dict[str, Any], cast(dict[str, Any], schema["properties"])["event_drafts"])
    items = cast(dict[str, Any], event_drafts["items"])
    branches = cast(list[dict[str, Any]], items["oneOf"])
    evidence_versions: set[str] = set()
    for branch in branches:
        branch_properties = cast(dict[str, Any], branch["properties"])
        schema_node = cast(dict[str, Any], branch_properties["schema"])
        schema_properties = cast(dict[str, Any], schema_node["properties"])
        if cast(dict[str, Any], schema_properties["name"])["const"] == "evidence_recorded":
            version_node = cast(dict[str, Any], schema_properties["version"])
            evidence_versions.add(cast(str, version_node["const"]))
    assert evidence_versions == {"1.0.0", "1.1.0"}
    encoded = repr(dict(schema))
    assert "opaque-unknown-event-draft" not in encoded
    assert "opaque_unknown" not in encoded


def test_presentation_examples_admit_under_catalog_models() -> None:
    start_examples = descriptor_for("start").input_schema["examples"]
    status_examples = descriptor_for("status").input_schema["examples"]
    publish_examples = descriptor_for("publish_work").input_schema["examples"]
    assert isinstance(start_examples, list) and len(start_examples) == 4
    assert isinstance(status_examples, list) and len(status_examples) == 1
    assert isinstance(publish_examples, list) and publish_examples
    start_example = start_examples[0]
    status_example = status_examples[0]
    publish_example = publish_examples[0]
    assert isinstance(start_example, dict)
    assert isinstance(status_example, dict)
    assert isinstance(publish_example, dict)
    for example in start_examples:
        StartRequest.model_validate(example)
    StatusRequest.model_validate(status_example)
    event_drafts = publish_example["event_drafts"]
    assert isinstance(event_drafts, list) and event_drafts
    first_draft = event_drafts[0]
    assert isinstance(first_draft, dict)
    schema = first_draft["schema"]
    assert isinstance(schema, dict)
    # The first example stays the smallest possible starting publication.
    assert schema["name"] == "plan_published"
    first_payload = first_draft["payload"]
    assert isinstance(first_payload, dict)
    assert first_payload["obligation_refs"] == []
    assert first_payload["no_obligations_reason"] == "single_atomic_change"

    # Every ordinary publishable family carries a worked example, and each one is a request an
    # agent could send unchanged. Copying a valid shape is the whole point of shipping these.
    exercised: set[str] = set()
    for example in publish_examples:
        assert isinstance(example, dict)
        PublishWorkRequest.model_validate(example)
        drafts = example["event_drafts"]
        assert isinstance(drafts, list)
        for draft in drafts:
            assert isinstance(draft, dict)
            draft_schema = draft["schema"]
            assert isinstance(draft_schema, dict)
            exercised.add(cast(str, draft_schema["name"]))
    assert exercised == ORDINARY_MCP_PUBLISH_EVENT_FAMILIES


def test_publish_work_examples_validate_against_advertised_input_schema() -> None:
    """Worked examples must validate against the contract MCP clients actually receive."""

    schema = descriptor_for("publish_work").input_schema
    examples = cast(list[JsonValue], schema["examples"])
    validator = cast(Any, Draft202012Validator(cast(Any, schema)))

    for index, example in enumerate(examples):
        errors = sorted(validator.iter_errors(example), key=lambda error: list(error.path))
        assert not errors, (index, tuple(error.json_path for error in errors))


def test_presentation_input_schema_is_projection_of_catalog_shape() -> None:
    for descriptor in TOOL_DESCRIPTORS["policy"]:
        presented = descriptor.input_schema
        catalog = descriptor.catalog_input_schema
        assert presented["type"] == catalog["type"]
        assert presented["additionalProperties"] == catalog["additionalProperties"]
        presented_required = presented["required"]
        catalog_required = catalog["required"]
        presented_properties = presented["properties"]
        catalog_properties = catalog["properties"]
        assert isinstance(presented_required, list)
        assert isinstance(catalog_required, list)
        assert isinstance(presented_properties, dict)
        assert isinstance(catalog_properties, dict)
        assert set(presented_required) == set(catalog_required)
        assert set(presented_properties) == set(catalog_properties)
        # tools/list may attach examples; catalog admission schemas do not require them.
        assert "examples" not in catalog


def test_read_guidance_uri_literal_matches_registered_resources() -> None:
    assert REGISTERED_GUIDANCE_URIS == tuple(item.uri for item in GUIDANCE_RESOURCES)


def test_read_guidance_descriptor_is_read_only_and_names_a_guidance_uri() -> None:
    descriptor = descriptor_for("read_guidance")
    assert descriptor.annotations.read_only is True
    assert descriptor.annotations.idempotent is True
    assert descriptor.annotations.destructive is False
    assert descriptor.annotations.open_world is False
    assert "yoetz://guidance/" in descriptor.description
    assert "bounded 4096-byte summary" in descriptor.description
    assert "not a ledger operation" in descriptor.description
