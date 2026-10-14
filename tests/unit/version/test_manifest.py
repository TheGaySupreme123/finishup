from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator

from yoetz.ports.diagnostics import StartupCheckOutcome
from yoetz.protocol.schemas import load_schema_catalog, request_result_schema_versions
from yoetz.version import (
    REVIEWED_RESOURCE_COUNT,
    ResourceIntegrityError,
    build_version_manifest,
    read_verified_resource,
    verify_resource_manifest,
    version_manifest_json,
)


def test_development_manifest_is_truthful_and_complete() -> None:
    manifest = build_version_manifest()

    assert manifest.support_status == "development_unverified"
    assert manifest.mcp_protocol_supported == ()
    assert manifest.codex_capability_profiles == ()
    assert manifest.service_capabilities == ()
    assert dict(manifest.subject_state_capabilities) == {"status": "absent"}
    assert manifest.limitations == (
        "development_unverified",
        "mcp_capability_unverified",
    )
    assert len(manifest.request_result_schema_versions) == 53
    assert dict(manifest.request_result_schema_versions)["setup-readiness"] == "1.0.0"
    assert dict(manifest.request_result_schema_versions)["setup-status"] == "2.0.0"
    assert dict(manifest.request_result_schema_versions)["isolation-report"] == "1.0.0"
    assert dict(manifest.request_result_schema_versions) == dict(
        request_result_schema_versions(load_schema_catalog())
    )
    assert len(manifest.event_schema_versions) == 29
    assert dict(manifest.event_schema_versions)["check_recorded"] == "1.4.0"
    assert dict(manifest.event_schema_versions)["finding_recorded"] == "1.4.0"
    counts = dict(manifest.resource_counts)
    assert len(manifest.resources) == REVIEWED_RESOURCE_COUNT == int(counts["total"])
    assert set(counts) == {
        "canonical_vectors",
        "guidance_resources",
        "migrations",
        "runtime_config_resources",
        "runtime_support_resources",
        "schema_resources",
        "skill_resources",
        "total",
    }
    assert sum(int(count) for name, count in counts.items() if name != "total") == int(
        counts["total"]
    )


def test_version_json_allows_installed_sdk_with_empty_tested_protocol_set() -> None:
    rendered = version_manifest_json(build_version_manifest())
    document = json.loads(rendered)
    schema = json.loads(Path("schemas/version/version-manifest-2.3.0.schema.json").read_text())

    assert document["mcp_sdk_version"]["status"] == "present"
    assert document["mcp_protocol_supported"] == []
    assert "mcp_capability_unverified" in document["limitations"]
    Draft202012Validator(schema).validate(document)  # pyright: ignore[reportUnknownMemberType]


def test_resource_manifest_verifies_every_installed_member() -> None:
    result = verify_resource_manifest(build_version_manifest())

    assert len(result) == 1
    assert result[0].outcome is StartupCheckOutcome.OK
    assert result[0].safe_details["resource_count"] == REVIEWED_RESOURCE_COUNT


def test_guidance_and_skill_source_package_bytes_are_identical() -> None:
    paths = (
        "guidance/agent-instructions.md",
        "guidance/coverage-and-receipts.md",
        "guidance/publication-policy.md",
        "guidance/workflow.md",
        "skills/codex/yoetz/SKILL.md",
        "skills/codex/yoetz/manifest.json",
        "skills/portable/yoetz/SKILL.md",
        "support/agent-plugins/1.0.0/mcp.schema.json",
        "support/agent-plugins/1.0.0/plugin.schema.json",
        "support/runtime-support.json",
    )

    for logical_name in paths:
        assert read_verified_resource(logical_name) == Path(logical_name).read_bytes()


def test_skill_does_not_advertise_parser_only_rollout_evidence() -> None:
    document = json.loads(read_verified_resource("skills/codex/yoetz/manifest.json"))

    assert document["codex_version_bounds"] == {
        "denied": [],
        "supported": [],
        "tested": [],
    }
    assert document["capability_profile_ids"] == []
    assert document["hooks_by_capability_profile"] == {}


def test_resource_reader_is_a_closed_logical_name_lookup() -> None:
    for name in ("../pyproject.toml", "/etc/passwd", "guidance/missing.md"):
        try:
            read_verified_resource(name)
        except ResourceIntegrityError:
            pass
        else:
            raise AssertionError(f"unexpected resource read: {name}")


def test_resource_integrity_error_exposes_bounded_reason_and_detail() -> None:
    error = ResourceIntegrityError(
        "support_resource_set_mismatch", detail="support/runtime-support.json"
    )

    assert str(error) == "support_resource_set_mismatch"
    assert error.reason == "support_resource_set_mismatch"
    assert error.detail == "support/runtime-support.json"
