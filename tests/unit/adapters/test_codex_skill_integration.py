"""Codex integration profile, resource, marker, and status tests."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from yoetz.adapters.integrations.codex_capability_cells import skill_manifest_capability_fields
from yoetz.adapters.integrations.codex_skill import (
    CODEX_HARNESS_PROFILE,
    CodexSkillIntegration,
    build_managed_marker,
    inspect_destination,
    load_packaged_skill_source,
)
from yoetz.domain.values import request_id
from yoetz.ports.integrations import (
    HarnessId,
    HarnessProfile,
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
from yoetz.protocol.canonical import JsonValue, canonical_digest, canonical_encode
from yoetz.protocol.errors import ProtocolValueError


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class _Resources:
    def __init__(self, files: dict[str, bytes]) -> None:
        self.files = files

    def read_bytes(self, package_path: str) -> bytes:
        try:
            return self.files[package_path]
        except KeyError as exc:
            raise FileNotFoundError(package_path) from exc


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _resources() -> _Resources:
    skill = (
        b"---\nname: yoetz\ndescription: Durable evidence guidance.\n"
        b"metadata:\n  short-description: Yoetz guidance\n---\n\n# Yoetz\n"
    )
    skill_manifest_body: dict[str, JsonValue] = {
        **dict(skill_manifest_capability_fields()),
        "guidance_version": "0.1.0",
        "harness": "codex",
        "managed_members": [],
        "protocol_version": "0.1",
        "schema": "yoetz.codex-skill-manifest/1",
        "skill": "yoetz",
        "skill_version": "0.1.0",
    }
    skill_manifest_body["member_digest"] = canonical_digest(skill_manifest_body)
    files = {
        "skills/codex/yoetz/SKILL.md": skill,
        "skills/codex/yoetz/manifest.json": canonical_encode(skill_manifest_body) + b"\n",
        "guidance/agent-instructions.md": b"# Agent instructions\n",
        "guidance/coverage-and-receipts.md": b"# Coverage and receipts\n",
        "guidance/publication-policy.md": b"# Publication policy\n",
        "guidance/request-templates.md": b"# Request templates\n",
        "guidance/workflow.md": b"# Workflow\n",
        "guidance/startup.md": b"# Startup\n",
        "guidance/recovery.md": b"# Recovery\n",
        "guidance/publication.md": b"# Publication\n",
        "guidance/review.md": b"# Review\n",
        "guidance/receipt.md": b"# Receipt\n",
        "guidance/delegation.md": b"# Delegation\n",
        "guidance/consent.md": b"# Consent\n",
        "guidance/page-delivery.md": b"# Page delivery\n",
    }
    installed_paths = {
        "SKILL.md": "skills/codex/yoetz/SKILL.md",
        "references/agent-instructions.md": "guidance/agent-instructions.md",
        "references/coverage-and-receipts.md": "guidance/coverage-and-receipts.md",
        "references/publication-policy.md": "guidance/publication-policy.md",
        "references/request-templates.md": "guidance/request-templates.md",
        "references/workflow.md": "guidance/workflow.md",
        "references/startup.md": "guidance/startup.md",
        "references/recovery.md": "guidance/recovery.md",
        "references/publication.md": "guidance/publication.md",
        "references/review.md": "guidance/review.md",
        "references/receipt.md": "guidance/receipt.md",
        "references/delegation.md": "guidance/delegation.md",
        "references/consent.md": "guidance/consent.md",
        "references/page-delivery.md": "guidance/page-delivery.md",
    }
    managed_members: list[JsonValue] = []
    for logical_name, package_path in installed_paths.items():
        data = files[package_path]
        managed_members.append(
            {
                "logical_name": logical_name,
                "origin": "harness_owned" if logical_name == "SKILL.md" else "shared_guidance",
                "role": "skill" if logical_name == "SKILL.md" else "guidance",
                "sha256": _digest(data),
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
    files["skills/codex/yoetz/manifest.json"] = canonical_encode(skill_manifest_body) + b"\n"
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
                "sha256": _digest(data),
                "size": len(data),
                "source_path": package_path,
            }
        )
    manifest_body: dict[str, JsonValue] = {
        "entries": entries,
        "package": "yoetz",
        "resource_set_version": "0.1.0",
        "schema": "yoetz.resource-manifest/1",
    }
    manifest_body["resource_set_digest"] = canonical_digest(manifest_body)
    files["manifest.json"] = canonical_encode(manifest_body) + b"\n"
    return _Resources(files)


def test_profile_does_not_promote_rollout_parser_evidence_to_skill_support() -> None:
    assert CODEX_HARNESS_PROFILE.harness_id is HarnessId.CODEX
    assert CODEX_HARNESS_PROFILE.skill_root == ".agents/skills/yoetz/"
    assert CODEX_HARNESS_PROFILE.capability_profile_ids == ()
    assert CODEX_HARNESS_PROFILE.supported_versions == ()
    assert dict(CODEX_HARNESS_PROFILE.hooks_by_capability_profile) == {}
    with pytest.raises(ProtocolValueError):
        HarnessProfile(
            HarnessId.CODEX,
            ".agents/skills/yoetz/",
            "codex_skill_frontmatter_v1",
            (),
            ("0.139.0",),
            {},
        )


def test_injected_source_is_manifest_verified_and_marker_is_path_free() -> None:
    source = load_packaged_skill_source(_resources())
    assert source.harness_id is HarnessId.CODEX
    assert source.harness_tested_set == ()
    assert tuple(file.relative_path for file in source.files) == (
        "SKILL.md",
        "manifest.json",
        "references/agent-instructions.md",
        "references/consent.md",
        "references/coverage-and-receipts.md",
        "references/delegation.md",
        "references/page-delivery.md",
        "references/publication-policy.md",
        "references/publication.md",
        "references/receipt.md",
        "references/recovery.md",
        "references/request-templates.md",
        "references/review.md",
        "references/startup.md",
        "references/workflow.md",
    )
    marker = build_managed_marker(source, IntegrationScope.TRUSTED_PROJECT)
    assert b"project_root" not in marker
    assert b"/Users/" not in marker


def test_source_mutation_fails_closed_without_checkout_fallback() -> None:
    resources = _resources()
    resources.files["guidance/workflow.md"] = b"changed\n"
    with pytest.raises(IntegrationError) as caught:
        load_packaged_skill_source(resources)
    assert caught.value.reason is IntegrationReason.SOURCE_INVALID


@pytest.mark.anyio
async def test_status_separates_filesystem_state_from_unprofiled_compatibility(
    tmp_path: Path,
) -> None:
    tmp_path.chmod(0o700)
    adapter = CodexSkillIntegration(_resources())
    target = IntegrationTarget(IntegrationScope.TRUSTED_PROJECT, str(tmp_path))
    status = await adapter.status_skill(HarnessId.CODEX, SkillStatusCommand(target))
    assert status.state is IntegrationState.ABSENT
    assert status.compatibility == "unsupported"
    assert not (tmp_path / ".agents").exists()

    command = SkillApplyCommand(
        request_id("req_00000000-0000-4000-8000-000000000031"),
        target,
        IntegrationAction.INSTALL,
        "sha256:" + "d" * 64,
        True,
        False,
    )
    with pytest.raises(IntegrationError) as caught:
        await adapter.install_skill(HarnessId.CODEX, command)
    assert caught.value.reason is IntegrationReason.VERSION_INCOMPATIBLE
    assert not (tmp_path / ".agents").exists()


@pytest.mark.anyio
async def test_explicit_allow_untested_installs_discoverable_project_skill(
    tmp_path: Path,
) -> None:
    tmp_path.chmod(0o700)
    adapter = CodexSkillIntegration(_resources(), allow_untested=True)
    target = IntegrationTarget(IntegrationScope.TRUSTED_PROJECT, str(tmp_path))
    request = request_id("req_00000000-0000-4000-8000-000000000032")
    preview = await adapter.preview_skill(
        HarnessId.CODEX,
        SkillPreviewCommand(request, target, IntegrationAction.INSTALL, False),
    )

    result = await adapter.install_skill(
        HarnessId.CODEX,
        SkillApplyCommand(
            request,
            target,
            IntegrationAction.INSTALL,
            preview.preview_digest,
            True,
            False,
        ),
    )

    assert result.state_after is IntegrationState.INSTALLED_EXACT
    status = await adapter.status_skill(HarnessId.CODEX, SkillStatusCommand(target))
    assert status.state is IntegrationState.INSTALLED_EXACT
    assert status.compatibility == "unsupported"
    assert (tmp_path / ".agents/skills/yoetz/SKILL.md").is_file()


@pytest.mark.anyio
async def test_symlinked_agents_and_skills_parents_are_target_unsafe(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    adapter = CodexSkillIntegration(_resources(), allow_untested=True)
    target = IntegrationTarget(IntegrationScope.TRUSTED_PROJECT, str(tmp_path))
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    (tmp_path / ".agents").symlink_to(outside, target_is_directory=True)

    with pytest.raises(IntegrationError) as caught:
        inspect_destination(target, load_packaged_skill_source(_resources()))
    assert caught.value.reason is IntegrationReason.TARGET_UNSAFE
    assert not (outside / "skills").exists()

    (tmp_path / ".agents").unlink()
    agents = tmp_path / ".agents"
    agents.mkdir(mode=0o700)
    (agents / "skills").symlink_to(outside, target_is_directory=True)
    with pytest.raises(IntegrationError) as caught_skills:
        await adapter.status_skill(HarnessId.CODEX, SkillStatusCommand(target))
    assert caught_skills.value.reason is IntegrationReason.TARGET_UNSAFE
    assert not (outside / "yoetz").exists()


@pytest.mark.anyio
async def test_parent_replaced_between_preview_and_apply_fails_closed(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    skills = tmp_path / ".agents" / "skills"
    skills.mkdir(parents=True, mode=0o700)
    (tmp_path / ".agents").chmod(0o700)
    adapter = CodexSkillIntegration(_resources(), allow_untested=True)
    target = IntegrationTarget(IntegrationScope.TRUSTED_PROJECT, str(tmp_path))
    request = request_id("req_00000000-0000-4000-8000-000000000033")
    preview = await adapter.preview_skill(
        HarnessId.CODEX,
        SkillPreviewCommand(request, target, IntegrationAction.INSTALL, False),
    )

    replaced = tmp_path / ".agents" / "skills.replaced"
    skills.rename(replaced)
    skills.mkdir(mode=0o700)

    with pytest.raises(IntegrationError) as caught:
        await adapter.install_skill(
            HarnessId.CODEX,
            SkillApplyCommand(
                request,
                target,
                IntegrationAction.INSTALL,
                preview.preview_digest,
                True,
                False,
            ),
        )
    assert caught.value.reason is IntegrationReason.PREVIEW_STALE
    assert not (skills / "yoetz").exists()
    assert not (replaced / "yoetz").exists()


@pytest.mark.anyio
async def test_parent_swap_after_path_identity_check_is_caught_by_retained_fd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#396: the descriptor itself, not a prior pathname check, binds the preview."""

    import yoetz.adapters.integrations.codex_skill as module

    tmp_path.chmod(0o700)
    skills = tmp_path / ".agents" / "skills"
    skills.mkdir(parents=True, mode=0o700)
    (tmp_path / ".agents").chmod(0o700)
    adapter = CodexSkillIntegration(_resources(), allow_untested=True)
    target = IntegrationTarget(IntegrationScope.TRUSTED_PROJECT, str(tmp_path))
    request = request_id("req_00000000-0000-4000-8000-000000000036")
    preview = await adapter.preview_skill(
        HarnessId.CODEX,
        SkillPreviewCommand(request, target, IntegrationAction.INSTALL, False),
    )

    original = module._skill_parent_identity  # pyright: ignore[reportPrivateUsage]
    replaced = tmp_path / ".agents" / "skills.replaced-after-check"

    def swap_after_identity(root: Path) -> str:
        identity = original(root)
        skills.rename(replaced)
        skills.mkdir(mode=0o700)
        monkeypatch.setattr(module, "_skill_parent_identity", original)
        return identity

    monkeypatch.setattr(module, "_skill_parent_identity", swap_after_identity)

    with pytest.raises(IntegrationError) as caught:
        await adapter.install_skill(
            HarnessId.CODEX,
            SkillApplyCommand(
                request,
                target,
                IntegrationAction.INSTALL,
                preview.preview_digest,
                True,
                False,
            ),
        )
    assert caught.value.reason is IntegrationReason.PREVIEW_STALE
    assert not (skills / "yoetz").exists()
    assert not (replaced / "yoetz").exists()


@pytest.mark.anyio
async def test_install_and_remove_stay_atomic_on_owner_directories(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    adapter = CodexSkillIntegration(_resources(), allow_untested=True)
    target = IntegrationTarget(IntegrationScope.TRUSTED_PROJECT, str(tmp_path))
    install_request = request_id("req_00000000-0000-4000-8000-000000000034")
    preview = await adapter.preview_skill(
        HarnessId.CODEX,
        SkillPreviewCommand(install_request, target, IntegrationAction.INSTALL, False),
    )
    await adapter.install_skill(
        HarnessId.CODEX,
        SkillApplyCommand(
            install_request,
            target,
            IntegrationAction.INSTALL,
            preview.preview_digest,
            True,
            False,
        ),
    )
    destination = tmp_path / ".agents/skills/yoetz"
    assert destination.is_dir()
    assert not destination.is_symlink()

    remove_request = request_id("req_00000000-0000-4000-8000-000000000035")
    remove_preview = await adapter.preview_skill(
        HarnessId.CODEX,
        SkillPreviewCommand(remove_request, target, IntegrationAction.REMOVE, False),
    )
    await adapter.remove_skill(
        HarnessId.CODEX,
        SkillApplyCommand(
            remove_request,
            target,
            IntegrationAction.REMOVE,
            remove_preview.preview_digest,
            True,
            False,
        ),
    )
    assert not destination.exists()


def test_package_import_has_no_filesystem_side_effect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    __import__("yoetz.adapters.integrations")
    assert list(tmp_path.iterdir()) == []
