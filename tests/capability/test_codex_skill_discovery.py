"""Codex skill discovery and safe integration capability evidence.

Non-live cells prove verified skill resource digests, isolated preview/modification protection via
an injected self-consistent skill source, and that app-server discovery claims stay unsupported
while harness profiles are unfrozen. Live ``skills/list`` / trigger cells require
``FINISHUP_LIVE_CODEX=1``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from capability.evidence import (
    CapabilityCase,
    EvidenceOutcome,
    Observation,
    bytes_digest,
    codex_profiles_frozen,
    live_codex_authorized,
    record_and_write,
    runtime_capability_context,
)
from finishup.adapters.integrations.codex_capability_cells import skill_manifest_capability_fields
from finishup.adapters.integrations.codex_skill import (
    CODEX_HARNESS_PROFILE,
    CodexSkillIntegration,
    build_managed_marker,
    expected_skill_member_paths,
    load_packaged_skill_source,
)
from finishup.domain.values import request_id
from finishup.ports.integrations import (
    HarnessId,
    IntegrationAction,
    IntegrationError,
    IntegrationReason,
    IntegrationScope,
    IntegrationState,
    IntegrationTarget,
    SkillApplyCommand,
    SkillPreviewCommand,
    SkillStatusCommand,
)
from finishup.protocol.canonical import JsonValue, canonical_digest, canonical_encode
from finishup.version import read_verified_resource

_TEST_REVISION = bytes_digest(Path(__file__).read_bytes())
_VERSION = "0.139.0"


class _Resources:
    def __init__(self, files: dict[str, bytes]) -> None:
        self.files = files

    def read_bytes(self, package_path: str) -> bytes:
        try:
            return self.files[package_path]
        except KeyError as exc:
            raise FileNotFoundError(package_path) from exc


def _injectable_skill_resources() -> _Resources:
    """Build a self-consistent skill/resource bundle for isolated integration probes."""

    skill = (
        b"---\nname: finishup\ndescription: Durable evidence guidance.\n"
        b"metadata:\n  short-description: FinishUP guidance\n---\n\n# FinishUP\n"
    )
    skill_manifest_body: dict[str, JsonValue] = {
        **dict(skill_manifest_capability_fields()),
        "guidance_version": "0.1.0",
        "harness": "codex",
        "managed_members": [],
        "protocol_version": "0.1",
        "schema": "yoetz.codex-skill-manifest/1",
        "skill": "finishup",
        "skill_version": "0.1.0",
    }
    skill_manifest_body["member_digest"] = canonical_digest(skill_manifest_body)
    # Derived from the adapter's own expected inventory so the fixture cannot go stale.
    installed_paths = {
        logical: "skills/codex/finishup/SKILL.md"
        if logical == "SKILL.md"
        else logical.replace("references/", "guidance/", 1)
        for logical in expected_skill_member_paths()
        if logical != "manifest.json"
    }
    files: dict[str, bytes] = {
        "skills/codex/finishup/SKILL.md": skill,
        "skills/codex/finishup/manifest.json": canonical_encode(skill_manifest_body) + b"\n",
    }
    for package_path in installed_paths.values():
        if package_path not in files:
            title = Path(package_path).stem.replace("-", " ").capitalize()
            files[package_path] = f"# {title}\n".encode()
    managed_members: list[JsonValue] = []
    for logical_name, package_path in installed_paths.items():
        data = files[package_path]
        managed_members.append(
            {
                "logical_name": logical_name,
                "origin": "harness_owned" if logical_name == "SKILL.md" else "shared_guidance",
                "role": "skill" if logical_name == "SKILL.md" else "guidance",
                "sha256": bytes_digest(data),
                "size": len(data),
                **({} if logical_name == "SKILL.md" else {"source_logical_name": package_path}),
            }
        )
    managed_members.insert(
        1,
        {
            "identity_status": "self_excluded",
            "logical_name": "manifest.json",
            "origin": "harness_owned",
            "role": "compatibility_manifest",
        },
    )
    skill_manifest_body["managed_members"] = managed_members
    skill_manifest_body.pop("member_digest")
    skill_manifest_body["member_digest"] = canonical_digest(skill_manifest_body)
    files["skills/codex/finishup/manifest.json"] = canonical_encode(skill_manifest_body) + b"\n"
    entries: list[JsonValue] = []
    for package_path, data in sorted(files.items(), key=lambda item: item[0].encode("ascii")):
        entries.append(
            {
                "kind": "skill" if package_path.endswith("SKILL.md") else "skill_reference",
                "logical_name": package_path,
                "media_type": "text/markdown"
                if package_path.endswith(".md")
                else "application/json",
                "package_path": package_path,
                "sha256": bytes_digest(data),
                "size": len(data),
                "source_path": package_path,
            }
        )
    manifest_body: dict[str, JsonValue] = {
        "entries": entries,
        "package": "finishup",
        "resource_set_version": "0.1.0",
        "schema": "yoetz.resource-manifest/1",
    }
    manifest_body["resource_set_digest"] = canonical_digest(manifest_body)
    files["manifest.json"] = canonical_encode(manifest_body) + b"\n"
    return _Resources(files)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def test_verified_skill_resources_have_stable_digests(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir(mode=0o700)
    skill = read_verified_resource("skills/codex/finishup/SKILL.md")
    manifest = read_verified_resource("skills/codex/finishup/manifest.json")
    assert skill.startswith(b"---")
    assert b"name: finishup" in skill
    assert CODEX_HARNESS_PROFILE.skill_root == ".agents/skills/finishup/"

    context = runtime_capability_context(
        fixture_digest=bytes_digest(skill + manifest),
        test_revision=_TEST_REVISION,
        config_profile_digest=canonical_digest({"skill_root": "agents_skills_finishup"}),
        external_tool="codex",
        external_version=_VERSION,
        integration_channel="codex_skill",
    )
    evidence = record_and_write(
        CapabilityCase(
            case_id="SKL-001",
            requirement_id="ADR-005.skill-discovery",
            claim_id="E-002.skill-parity",
            capability_family="codex_skill_discovery",
            required_observation_codes=frozenset(
                {"skill_digest_bound", "manifest_digest_bound", "harness_root_exact"}
            ),
            allowed_observation_codes=frozenset(
                {"skill_digest_bound", "manifest_digest_bound", "harness_root_exact"}
            ),
        ),
        context,
        (
            Observation("skill_digest_bound", digest_value=bytes_digest(skill)),
            Observation("manifest_digest_bound", digest_value=bytes_digest(manifest)),
            Observation("harness_root_exact", boolean_value=True),
        ),
        EvidenceOutcome.PASS,
        output_root=evidence_root,
    )
    assert evidence.outcome is EvidenceOutcome.PASS


def test_skill_and_guidance_define_exact_agent_attested_chat_authorization() -> None:
    skill = read_verified_resource("skills/codex/finishup/SKILL.md").decode("utf-8")
    guidance = read_verified_resource("guidance/agent-instructions.md").decode("utf-8")

    for entrypoint in (skill, guidance):
        assert "finishup://guidance/request-templates.md" in entrypoint
    for document in (read_verified_resource("guidance/request-templates.md").decode("utf-8"),):
        assert "agent-attested trust model, not host-verified proof" in document
        assert "explicitly instructs you in the current chat" in document
        assert "--provider-credential-stdin" in document
        assert "vault_initialize" in document
        assert "compromised agent could forge" in document


@pytest.mark.anyio
async def test_preview_and_modified_copy_protection_in_isolated_repo(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir(mode=0o700)
    project = tmp_path / "project"
    project.mkdir(mode=0o700)
    resources = _injectable_skill_resources()
    adapter = CodexSkillIntegration(resources)
    target = IntegrationTarget(IntegrationScope.TRUSTED_PROJECT, str(project))

    status = await adapter.status_skill(HarnessId.CODEX, SkillStatusCommand(target))
    assert status.state in {IntegrationState.ABSENT, IntegrationState.INCOMPATIBLE}
    assert status.compatibility == "unsupported"

    preview = await adapter.preview_skill(
        HarnessId.CODEX,
        SkillPreviewCommand(
            request_id("req_00000000-0000-4000-8000-000000000040"),
            target,
            IntegrationAction.INSTALL,
            False,
        ),
    )
    assert preview.preview_digest.startswith("sha256:")
    source = load_packaged_skill_source(resources)
    marker = build_managed_marker(source, IntegrationScope.TRUSTED_PROJECT)
    assert b"/Users/" not in marker
    assert b"project_root" not in marker

    skill_dir = project / ".agents" / "skills" / "finishup"
    skill_dir.mkdir(parents=True, mode=0o700)
    (skill_dir / "SKILL.md").write_bytes(b"user-modified-skill\n")
    before = (skill_dir / "SKILL.md").read_bytes()
    apply = SkillApplyCommand(
        request_id("req_00000000-0000-4000-8000-000000000041"),
        target,
        IntegrationAction.INSTALL,
        preview.preview_digest,
        True,
        False,
    )
    with pytest.raises(IntegrationError) as caught:
        await adapter.install_skill(HarnessId.CODEX, apply)
    assert caught.value.reason is IntegrationReason.VERSION_INCOMPATIBLE
    assert (skill_dir / "SKILL.md").read_bytes() == before

    context = runtime_capability_context(
        fixture_digest=bytes_digest(before),
        test_revision=_TEST_REVISION,
        config_profile_digest=canonical_digest({"cell": "modified_copy_protection"}),
        external_tool="codex",
        external_version=_VERSION,
        integration_channel="codex_skill",
    )
    evidence = record_and_write(
        CapabilityCase(
            case_id="SKL-002",
            requirement_id="ADR-005.skill-discovery",
            claim_id="E-002.skill-integration",
            capability_family="codex_skill_discovery",
            required_observation_codes=frozenset({"modified_copy_preserved", "marker_path_free"}),
            allowed_observation_codes=frozenset(
                {"modified_copy_preserved", "marker_path_free", "install_refused"}
            ),
        ),
        context,
        (
            Observation("modified_copy_preserved", boolean_value=True),
            Observation("marker_path_free", boolean_value=True),
            Observation("install_refused", boolean_value=True),
        ),
        EvidenceOutcome.PASS,
        output_root=evidence_root,
    )
    assert evidence.outcome is EvidenceOutcome.PASS


def test_app_server_discovery_claim_unsupported_while_unprofiled(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir(mode=0o700)
    assert CODEX_HARNESS_PROFILE.capability_profile_ids == ()
    assert CODEX_HARNESS_PROFILE.supported_versions == ()
    context = runtime_capability_context(
        fixture_digest=bytes_digest(b"skills-list-unprofiled"),
        test_revision=_TEST_REVISION,
        config_profile_digest=canonical_digest({"cell": "skills_list"}),
        external_tool="codex",
        external_version=_VERSION,
        integration_channel="codex_skill",
    )
    if codex_profiles_frozen():
        pytest.skip("frozen profiles move skills/list into the live matrix")
    evidence = record_and_write(
        CapabilityCase(
            case_id="SKL-003",
            requirement_id="ADR-005.skill-discovery",
            claim_id="E-002.skill-discovery",
            capability_family="codex_skill_discovery",
            required_observation_codes=frozenset({"profiles_frozen", "implicit_trigger_claimed"}),
            allowed_observation_codes=frozenset({"profiles_frozen", "implicit_trigger_claimed"}),
        ),
        context,
        (
            Observation("profiles_frozen", boolean_value=False),
            Observation("implicit_trigger_claimed", boolean_value=False),
        ),
        EvidenceOutcome.UNSUPPORTED,
        ("codex_skill_discovery_unprobed",),
        output_root=evidence_root,
    )
    assert evidence.outcome is EvidenceOutcome.UNSUPPORTED


@pytest.mark.live
def test_live_codex_skill_discovery_and_triggers(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir(mode=0o700)
    context = runtime_capability_context(
        fixture_digest=bytes_digest(b"live-skill-discovery"),
        test_revision=_TEST_REVISION,
        config_profile_digest=canonical_digest({"cell": "live_skill_discovery"}),
        external_tool="codex",
        external_version=_VERSION,
        integration_channel="codex_skill",
    )
    if not live_codex_authorized():
        evidence = record_and_write(
            CapabilityCase(
                case_id="SKL-LIVE-001",
                requirement_id="ADR-005.skill-discovery",
                claim_id="E-002.skill-discovery-live",
                capability_family="codex_skill_discovery",
                required_observation_codes=frozenset({"live_authorized"}),
                allowed_observation_codes=frozenset({"live_authorized"}),
            ),
            context,
            (Observation("live_authorized", boolean_value=False),),
            EvidenceOutcome.UNSUPPORTED,
            ("live_codex_not_authorized",),
            output_root=evidence_root,
        )
        assert evidence.outcome is EvidenceOutcome.UNSUPPORTED
        return
    pytest.fail("live Codex skill discovery authorized; observe skills/list before pass")
