"""Codex plugin renderer and fail-closed installer unit tests."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from pathlib import Path

import pytest

from yoetz.adapters.integrations import codex_plugin as plugin_mod
from yoetz.adapters.integrations.codex_capability_cells import skill_manifest_capability_fields
from yoetz.adapters.integrations.codex_plugin import (
    PluginHookPresence,
    codex_supports_async_hooks,
    inspect_plugin,
    install_plugin,
    parse_hooks_json,
    render_plugin_tree,
)
from yoetz.adapters.integrations.codex_skill import SkillResourceSource, load_packaged_skill_source
from yoetz.ports.integrations import (
    HarnessId,
    IntegrationError,
    IntegrationFile,
    IntegrationReason,
    IntegrationScope,
    IntegrationState,
    IntegrationTarget,
    SkillSource,
)
from yoetz.protocol.canonical import JsonValue, canonical_digest, canonical_encode


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
    guidance_files = {
        "references/agent-instructions.md": (
            "guidance/agent-instructions.md",
            b"# Agent instructions\n",
        ),
        "references/coverage-and-receipts.md": (
            "guidance/coverage-and-receipts.md",
            b"# Coverage and receipts\n",
        ),
        "references/publication-policy.md": (
            "guidance/publication-policy.md",
            b"# Publication policy\n",
        ),
        "references/request-templates.md": (
            "guidance/request-templates.md",
            b"# Request templates\n",
        ),
        "references/workflow.md": ("guidance/workflow.md", b"# Workflow\n"),
        "references/startup.md": ("guidance/startup.md", b"# Startup\n"),
        "references/recovery.md": ("guidance/recovery.md", b"# Recovery\n"),
        "references/publication.md": ("guidance/publication.md", b"# Publication\n"),
        "references/review.md": ("guidance/review.md", b"# Review\n"),
        "references/receipt.md": ("guidance/receipt.md", b"# Receipt\n"),
        "references/delegation.md": ("guidance/delegation.md", b"# Delegation\n"),
        "references/consent.md": ("guidance/consent.md", b"# Consent\n"),
        "references/page-delivery.md": ("guidance/page-delivery.md", b"# Page delivery\n"),
    }
    managed_members: list[JsonValue] = [
        {
            "logical_name": "SKILL.md",
            "origin": "harness_owned",
            "role": "skill",
            "sha256": _digest(skill),
            "size": len(skill),
        },
        {
            "identity_status": "self_excluded",
            "logical_name": "manifest.json",
            "origin": "harness_owned",
            "role": "compatibility_manifest",
        },
    ]
    managed_members.extend(
        {
            "logical_name": installed_path,
            "origin": "shared_guidance",
            "role": "guidance",
            "sha256": _digest(data),
            "size": len(data),
            "source_logical_name": package_path,
        }
        for installed_path, (package_path, data) in guidance_files.items()
    )
    skill_manifest_body: dict[str, JsonValue] = {
        **dict(skill_manifest_capability_fields()),
        "guidance_version": "0.1.0",
        "harness": "codex",
        "managed_members": managed_members,
        "protocol_version": "0.1",
        "schema": "yoetz.codex-skill-manifest/1",
        "skill": "yoetz",
        "skill_version": "0.1.0",
    }
    skill_manifest_body["member_digest"] = canonical_digest(skill_manifest_body)
    files = {
        "skills/codex/yoetz/SKILL.md": skill,
        "skills/codex/yoetz/manifest.json": canonical_encode(skill_manifest_body) + b"\n",
        **{package_path: data for package_path, data in guidance_files.values()},
    }
    entries: list[JsonValue] = []
    for package_path, data in sorted(files.items(), key=lambda item: item[0].encode("ascii")):
        entries.append(
            {
                "kind": "skill" if package_path.endswith("SKILL.md") else "skill_reference",
                "logical_name": package_path,
                "media_type": (
                    "text/markdown" if package_path.endswith(".md") else "application/json"
                ),
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


def _enable_supported_profile(
    monkeypatch: pytest.MonkeyPatch,
    resources: _Resources,
) -> None:
    fake_source = SkillSource(
        HarnessId.CODEX,
        "0.1.0",
        "0.1",
        ("0.146.0",),
        "sha256:" + "a" * 64,
        (
            IntegrationFile(
                "SKILL.md",
                len(resources.files["skills/codex/yoetz/SKILL.md"]),
                "sha256:" + "b" * 64,
                "text/markdown",
            ),
        ),
    )

    def _fake_load(_resource_source: SkillResourceSource | None = None) -> SkillSource:
        return fake_source

    monkeypatch.setattr(plugin_mod, "load_packaged_skill_source", _fake_load)


def test_render_plugin_tree_wires_observation_and_compat_hooks() -> None:
    tree = render_plugin_tree(resource_source=_resources())
    assert ".codex-plugin/plugin.json" in tree
    assert "hooks/hooks.json" in tree
    assert ".mcp.json" in tree
    assert "skills/yoetz/SKILL.md" in tree
    hooks = tree["hooks/hooks.json"].decode("utf-8")
    assert "yoetz hooks user-prompt-submit --workspace ." in hooks
    assert "yoetz hooks post-tool-use" in hooks
    # The re-ground probe names its workspace like every other rendered hook (#659).
    assert "yoetz hooks session-start --workspace ." in hooks
    assert "yoetz hooks observe --workspace . --event SessionStart" in hooks
    assert "yoetz hooks spool --workspace . --event PreToolUse" in hooks
    assert "yoetz hooks spool --workspace . --event PermissionRequest" in hooks
    assert "yoetz hooks observe --workspace . --event SubagentStop" in hooks
    assert "mcp__yoetz__start" in hooks
    assert "resume|compact" in hooks


def _observe_handler(parsed: Mapping[str, object], event: str) -> dict[str, object]:
    groups = parsed["hooks"][event]  # type: ignore[index, call-overload]
    for group in groups:  # type: ignore[union-attr]
        for handler in group["hooks"]:  # type: ignore[index, call-overload]
            if str(handler["command"]).startswith("yoetz hooks observe "):  # type: ignore[index]
                return dict(handler)  # type: ignore[arg-type, call-overload]
    raise AssertionError(f"no observe handler declared for {event}")


def _spool_handler(parsed: Mapping[str, object], event: str) -> dict[str, object]:
    groups = parsed["hooks"][event]  # type: ignore[index, call-overload]
    for group in groups:  # type: ignore[union-attr]
        for handler in group["hooks"]:  # type: ignore[index, call-overload]
            if str(handler["command"]).startswith("yoetz hooks spool "):  # type: ignore[index]
                return dict(handler)  # type: ignore[arg-type, call-overload]
    raise AssertionError(f"no spool handler declared for {event}")


def test_observe_hook_execution_modes_use_async_only_on_capable_hosts() -> None:
    """#209/#271: capable hosts use async; advice handlers remain synchronous.

    Sync PreToolUse/PostToolUse at an unmeetable 3s added ~6s to every tool
    call and had both hooks SIGKILLed at the deadline. The contract is now:
    handlers that always emit ``{}`` declare ``"async": true`` only when the
    exact host can register it, handlers that return
    ``additionalContext`` or a Stop ``decision: block`` stay synchronous at 10s,
    and SessionEnd stays inside the host's hard 3s clamp so it never draws a
    per-session warning. SessionEnd is not advice-safe (#222): the host
    discards its stdout.
    """

    from yoetz.cli.observe_hooks import ADVICE_SAFE_EVENTS, SUPPORTED_HOOK_EVENTS

    parsed = dict(
        parse_hooks_json(
            render_plugin_tree(resource_source=_resources(), codex_version="0.148.0-alpha.6")[
                "hooks/hooks.json"
            ]
        )
    )
    pure_ingress = (
        "PermissionRequest",
        "PreCompact",
        "PostCompact",
        "SubagentStart",
        "SubagentStop",
    )
    # The async split's real invariant: async iff the handler never returns
    # host-consumed advice or a Stop decision. SessionEnd is sync only because
    # Codex downgrades async SessionEnd; it is not advice-safe. If someone adds
    # an event to ADVICE_SAFE_EVENTS while it is still declared async here,
    # Codex would silently drop its advice or decision.
    assert set(pure_ingress) == (
        SUPPORTED_HOOK_EVENTS
        - ADVICE_SAFE_EVENTS
        - {"PreToolUse", "UserPromptSubmit", "SessionEnd", "PermissionDecision"}
    )
    for event in pure_ingress:
        handler = _observe_handler(parsed, event)
        assert handler.get("async") is True, f"{event} observe must not block the session"
        assert handler["timeout"] == 10, f"{event} needs an explicit modest timeout"
    for event in ("SessionStart", "PreToolUse", "PostToolUse", "Stop"):
        handler = _observe_handler(parsed, event)
        assert "async" not in handler, f"{event} returns advice or a Stop decision; async drops it"
        assert handler["timeout"] == 10, f"{event} declared timeout must be meetable"
    session_end = _observe_handler(parsed, "SessionEnd")
    assert "async" not in session_end, "Codex downgrades async SessionEnd with a warning"
    assert session_end["timeout"] == 3, "Codex hard-clamps SessionEnd timeouts above 3s"
    assert "SessionEnd" not in ADVICE_SAFE_EVENTS


@pytest.mark.parametrize(
    ("version", "supported"),
    [
        (None, False),
        ("", False),
        ("0.147.0", False),
        ("0.148.0-alpha.5", False),
        ("0.148.0-alpha.6", True),
        ("0.148.0a6", True),
        ("0.148.0-alpha.19", True),
        ("0.148.0-beta.1", True),
        ("0.148.0", True),
        ("1.0.0", True),
        ("0.148", False),
        ("0.148.0/not-a-version", False),
        ("9" * 129, False),
    ],
)
def test_async_hook_capability_fails_closed(version: str | None, supported: bool) -> None:
    assert codex_supports_async_hooks(version) is supported


@pytest.mark.parametrize("version", [None, "0.146.0", "0.147.0", "not-a-version"])
def test_unsupported_or_unknown_hosts_keep_all_ingress_handlers_synchronous(
    version: str | None,
) -> None:
    parsed = dict(
        parse_hooks_json(
            render_plugin_tree(resource_source=_resources(), codex_version=version)[
                "hooks/hooks.json"
            ]
        )
    )
    for event in ("PreToolUse", "PermissionRequest"):
        handler = _spool_handler(parsed, event)
        assert "async" not in handler
        assert handler["timeout"] == 10
    for event in (
        "PreCompact",
        "PostCompact",
        "SubagentStart",
        "SubagentStop",
    ):
        handler = _observe_handler(parsed, event)
        assert "async" not in handler
        assert handler["timeout"] == 10


def test_install_refuses_when_tested_set_empty(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    source = load_packaged_skill_source(_resources())
    assert source.harness_tested_set == ()
    with pytest.raises(IntegrationError) as caught:
        install_plugin(
            IntegrationTarget(IntegrationScope.TRUSTED_PROJECT, str(tmp_path)),
            resource_source=_resources(),
        )
    assert caught.value.reason is IntegrationReason.VERSION_INCOMPATIBLE
    assert not (tmp_path / ".agents").exists()


def test_install_allow_untested_installs_hooks(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    target = IntegrationTarget(IntegrationScope.TRUSTED_PROJECT, str(tmp_path))
    inspection = install_plugin(target, resource_source=_resources(), allow_untested=True)
    assert inspection.presence is PluginHookPresence.INSTALLED
    assert inspection.state is IntegrationState.INSTALLED_EXACT
    assert inspection.trust_observable is False
    assert (tmp_path / ".agents/plugins/yoetz/hooks/hooks.json").is_file()


def test_install_refuses_locally_modified_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tmp_path.chmod(0o700)
    resources = _resources()
    _enable_supported_profile(monkeypatch, resources)
    target = IntegrationTarget(IntegrationScope.TRUSTED_PROJECT, str(tmp_path))
    first = install_plugin(target, resource_source=resources)
    assert first.presence is PluginHookPresence.INSTALLED
    assert first.trust_observable is False

    hooks_path = tmp_path / ".agents/plugins/yoetz/hooks/hooks.json"
    hooks_path.write_bytes(hooks_path.read_bytes() + b"# modified\n")
    with pytest.raises(IntegrationError) as caught:
        install_plugin(target, resource_source=resources)
    assert caught.value.reason is IntegrationReason.MODIFIED_COPY
    assert caught.value.safe_details == {
        "relative_path": "hooks/hooks.json",
        "replace_modified": True,
    }


def test_install_replaces_prior_managed_variant_render_without_replace_modified(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#387: a marker-consistent prior render (e.g. async-variant hooks) is not an owner edit.

    A wizard that previously wrote the host-rendered async form must be able to
    return the tree to the canonical render without the ``modified_copy`` refusal
    reserved for genuinely modified files.
    """

    tmp_path.chmod(0o700)
    resources = _resources()
    _enable_supported_profile(monkeypatch, resources)
    target = IntegrationTarget(IntegrationScope.TRUSTED_PROJECT, str(tmp_path))
    install_plugin(target, resource_source=resources, codex_version="0.148.0-alpha.6")
    hooks_path = tmp_path / ".agents/plugins/yoetz/hooks/hooks.json"
    assert b'"async":true' in hooks_path.read_bytes()

    inspection = install_plugin(target, resource_source=resources, codex_version=None)

    assert inspection.presence is PluginHookPresence.INSTALLED
    assert b'"async":true' not in hooks_path.read_bytes()


def test_plugin_tree_matches_marker_accepts_only_marker_consistent_trees() -> None:
    from yoetz.adapters.integrations.codex_plugin import (
        plugin_tree_matches_marker,
        render_plugin_install_tree,
    )

    tree = render_plugin_install_tree(resource_source=_resources())
    assert plugin_tree_matches_marker(tree) is True

    modified = dict(tree)
    modified["hooks/hooks.json"] = modified["hooks/hooks.json"] + b"# modified\n"
    assert plugin_tree_matches_marker(modified) is False

    extra = dict(tree)
    extra["credential123"] = b"not managed"
    assert plugin_tree_matches_marker(extra) is False

    missing = dict(tree)
    del missing[".yoetz-plugin-install.json"]
    assert plugin_tree_matches_marker(missing) is False

    tampered = dict(tree)
    tampered[".yoetz-plugin-install.json"] = tampered[".yoetz-plugin-install.json"].replace(
        b"yoetz.codex-plugin-install/1", b"yoetz.codex-plugin-install/9"
    )
    assert plugin_tree_matches_marker(tampered) is False


def test_install_refuses_symlinked_plugin_ancestor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tmp_path.chmod(0o700)
    resources = _resources()
    _enable_supported_profile(monkeypatch, resources)
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    (tmp_path / ".agents").symlink_to(outside, target_is_directory=True)

    with pytest.raises(IntegrationError) as caught:
        install_plugin(
            IntegrationTarget(IntegrationScope.TRUSTED_PROJECT, str(tmp_path)),
            resource_source=resources,
        )

    assert caught.value.reason is IntegrationReason.TARGET_UNSAFE
    assert not (outside / "plugins").exists()


def test_install_restores_previous_plugin_when_swap_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tmp_path.chmod(0o700)
    resources = _resources()
    _enable_supported_profile(monkeypatch, resources)
    target = IntegrationTarget(IntegrationScope.TRUSTED_PROJECT, str(tmp_path))
    install_plugin(target, resource_source=resources)
    destination = tmp_path / ".agents/plugins/yoetz"
    marker_path = destination / ".yoetz-plugin-install.json"
    original_marker = marker_path.read_bytes()
    real_replace = plugin_mod.os.replace

    def _fail_stage_swap(source: Path, target_path: Path) -> None:
        if source.name.startswith(".yoetz.plugin-stage-") and target_path == destination:
            raise OSError("injected stage swap failure")
        real_replace(source, target_path)

    monkeypatch.setattr(plugin_mod.os, "replace", _fail_stage_swap)
    with pytest.raises(IntegrationError) as caught:
        install_plugin(target, replace_modified=True, resource_source=resources)

    assert caught.value.reason is IntegrationReason.WRITE_FAILED
    assert destination.is_dir()
    assert marker_path.read_bytes() == original_marker


def test_inspect_absent_and_trust_not_observable(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    inspection = inspect_plugin(
        IntegrationTarget(IntegrationScope.TRUSTED_PROJECT, str(tmp_path)),
        resource_source=_resources(),
    )
    assert inspection.presence is PluginHookPresence.ABSENT
    assert inspection.trust_observable is False
    assert "codex_hook_trust_not_observable_from_installation_state" in inspection.notes
