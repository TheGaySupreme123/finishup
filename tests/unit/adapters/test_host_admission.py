"""Host auto-review admission adapter (issue #467).

Every host's automatic reviewer refuses the policy-route ``check`` because the owner's privacy
grant is invisible to it. These tests pin the rules that make the admission entry an honest
mirror of that grant: exact-entry recognition, no edits beside a foreign rule, ``unknown`` for a
file that could not be read, digest-bound writes, and reverse transitions that remove exactly what
FinishUP wrote.
"""

from __future__ import annotations

import json
import os
import tomllib
from pathlib import Path

import pytest

from finishup.adapters.integrations import host_admission as module
from finishup.adapters.integrations.host_admission import (
    CLAUDE_CHECK_TOOL_NAME,
    CLAUDE_EXTERNAL_CHECK_TOOL_NAME,
    CLAUDE_PLUGIN_CHECK_TOOL_NAME,
    CODEX_EXTERNAL_ADMISSION_TABLE,
    CODEX_PLUGIN_ADMISSION_TABLE,
    CURSOR_CLI_PLUGIN_ENTRY,
    CURSOR_IDE_ENTRY,
    HostAdmissionAction,
    HostAdmissionError,
    HostAdmissionReason,
    HostAdmissionState,
    apply_host_admission,
    observe_host_admission,
    preview_host_admission,
    sweep_host_admission,
)


def _grant(
    host: module.HostAdmissionHost, root: Path, **kwargs: object
) -> module.HostAdmissionResult:
    if host == "claude" and "owner" not in kwargs:
        kwargs["owner"] = "plugin"
    preview = preview_host_admission(
        host,
        root,
        HostAdmissionAction.GRANT,
        route_profile="policy",
        grant_permits=True,
        **kwargs,  # type: ignore[arg-type]
    )
    return apply_host_admission(preview, root, accepted_preview_digest=preview.preview_digest)


def _revoke(
    host: module.HostAdmissionHost, root: Path, **kwargs: object
) -> module.HostAdmissionResult:
    preview = preview_host_admission(
        host,
        root,
        HostAdmissionAction.REVOKE,
        route_profile=None,
        grant_permits=None,
        **kwargs,  # type: ignore[arg-type]
    )
    return apply_host_admission(preview, root, accepted_preview_digest=preview.preview_digest)


# --- gating -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("route", "grant", "reason"),
    [
        (None, True, HostAdmissionReason.ROUTE_UNOBSERVED),
        ("strict", True, HostAdmissionReason.ROUTE_NOT_POLICY),
        ("policy", None, HostAdmissionReason.GRANT_UNVERIFIABLE),
        ("policy", False, HostAdmissionReason.GRANT_NOT_PERMITTING),
    ],
)
def test_grant_is_refused_unless_the_route_is_policy_and_the_grant_permits_review(
    tmp_path: Path, route: str | None, grant: bool | None, reason: HostAdmissionReason
) -> None:
    """The strict-route negative control: no entry is offered or written, on any host."""

    for host in module.ADMISSION_HOSTS:
        with pytest.raises(HostAdmissionError) as failure:
            preview_host_admission(
                host,
                tmp_path,
                HostAdmissionAction.GRANT,
                route_profile=route,
                grant_permits=grant,
                owner="external",
            )
        assert failure.value.reason is reason
    assert sorted(os.listdir(tmp_path)) == []


def test_revoke_needs_neither_route_nor_grant(tmp_path: Path) -> None:
    """The way out stays open even when the service and the host route cannot be read."""

    _grant("claude", tmp_path)
    result = _revoke("claude", tmp_path)
    assert result.action is HostAdmissionAction.REVOKE
    assert result.state_after is HostAdmissionState.ABSENT
    assert not (tmp_path / ".claude" / "settings.local.json").exists()


def test_every_host_grant_needs_an_observed_owner(tmp_path: Path) -> None:
    for host in module.ADMISSION_HOSTS:
        with pytest.raises(HostAdmissionError) as failure:
            preview_host_admission(
                host,  # type: ignore[arg-type]
                tmp_path,
                HostAdmissionAction.GRANT,
                route_profile="policy",
                grant_permits=True,
            )
        assert failure.value.reason is HostAdmissionReason.OWNER_REQUIRED


# --- Claude Code --------------------------------------------------------------------------


def test_claude_grant_writes_only_the_exact_allow_rule_and_preserves_the_rest(
    tmp_path: Path,
) -> None:
    settings = tmp_path / ".claude" / "settings.local.json"
    settings.parent.mkdir()
    settings.write_text(
        json.dumps({"permissions": {"allow": ["Bash(git status)"]}, "env": {"FOO": "1"}}),
        encoding="utf-8",
    )
    before = observe_host_admission("claude", tmp_path)
    assert before.state is HostAdmissionState.ABSENT

    result = _grant("claude", tmp_path)

    assert result.state_after is HostAdmissionState.PRESENT
    assert result.surfaces_changed == (".claude/settings.local.json",)
    written = json.loads(settings.read_text(encoding="utf-8"))
    assert written == {
        "permissions": {"allow": ["Bash(git status)", CLAUDE_CHECK_TOOL_NAME]},
        "env": {"FOO": "1"},
    }
    assert oct(settings.stat().st_mode & 0o777) == "0o600"
    after = observe_host_admission("claude", tmp_path)
    assert after.state is HostAdmissionState.PRESENT
    assert after.entries[0].detail == "allow"

    # Idempotent: a second grant is a no-op preview, not a duplicate rule.
    again = preview_host_admission(
        "claude",
        tmp_path,
        HostAdmissionAction.GRANT,
        route_profile="policy",
        grant_permits=True,
        owner="plugin",
    )
    assert again.action is HostAdmissionAction.NOOP
    assert again.files_after == {}


@pytest.mark.parametrize(
    ("owner", "expected"),
    [
        ("external", CLAUDE_EXTERNAL_CHECK_TOOL_NAME),
        ("plugin", CLAUDE_PLUGIN_CHECK_TOOL_NAME),
    ],
)
def test_claude_grant_follows_the_observed_route_owner(
    tmp_path: Path, owner: module.McpOwnerForm, expected: str
) -> None:
    _grant("claude", tmp_path, owner=owner)
    settings = json.loads(
        (tmp_path / ".claude" / "settings.local.json").read_text(encoding="utf-8")
    )
    assert settings == {"permissions": {"allow": [expected]}}
    assert (
        observe_host_admission("claude", tmp_path, owner=owner).state is HostAdmissionState.PRESENT
    )


def test_claude_revoke_removes_exactly_the_entry_and_leaves_owner_rules(tmp_path: Path) -> None:
    settings = tmp_path / ".claude" / "settings.local.json"
    settings.parent.mkdir()
    settings.write_text(
        json.dumps({"permissions": {"allow": ["Bash(git status)"], "deny": ["WebFetch"]}}),
        encoding="utf-8",
    )
    _grant("claude", tmp_path)
    _revoke("claude", tmp_path)
    assert json.loads(settings.read_text(encoding="utf-8")) == {
        "permissions": {"allow": ["Bash(git status)"], "deny": ["WebFetch"]}
    }


def test_claude_checkpoint_writes_the_ask_rule_and_revoke_finds_it(tmp_path: Path) -> None:
    result = _grant("claude", tmp_path, checkpoint=True)
    assert result.state_after is HostAdmissionState.PRESENT
    settings = tmp_path / ".claude" / "settings.local.json"
    assert json.loads(settings.read_text(encoding="utf-8")) == {
        "permissions": {"ask": [CLAUDE_CHECK_TOOL_NAME]}
    }
    assert observe_host_admission("claude", tmp_path).entries[0].detail == "ask"
    assert _revoke("claude", tmp_path).state_after is HostAdmissionState.ABSENT


def test_claude_grant_moves_the_entry_between_allow_and_ask_instead_of_a_silent_noop(
    tmp_path: Path,
) -> None:
    """PR #478 review: `grant` after `grant --checkpoint` (or the reverse) is a mode change."""

    settings = tmp_path / ".claude" / "settings.local.json"
    _grant("claude", tmp_path)
    assert observe_host_admission("claude", tmp_path).entries[0].detail == "allow"

    to_ask = _grant("claude", tmp_path, checkpoint=True)
    assert to_ask.action is HostAdmissionAction.GRANT
    assert to_ask.surfaces_changed == (".claude/settings.local.json",)
    assert json.loads(settings.read_text(encoding="utf-8")) == {
        "permissions": {"ask": [CLAUDE_CHECK_TOOL_NAME]}
    }
    assert observe_host_admission("claude", tmp_path).entries[0].detail == "ask"

    back_to_allow = _grant("claude", tmp_path)
    assert back_to_allow.action is HostAdmissionAction.GRANT
    assert json.loads(settings.read_text(encoding="utf-8")) == {
        "permissions": {"allow": [CLAUDE_CHECK_TOOL_NAME]}
    }
    assert observe_host_admission("claude", tmp_path).entries[0].detail == "allow"


def test_claude_same_mode_grant_stays_a_noop_and_a_mode_change_preserves_owner_rules(
    tmp_path: Path,
) -> None:
    settings = tmp_path / ".claude" / "settings.local.json"
    settings.parent.mkdir()
    settings.write_text(
        json.dumps(
            {
                "permissions": {"allow": ["Bash(git status)"], "ask": ["WebFetch"]},
                "env": {"FOO": "1"},
            }
        ),
        encoding="utf-8",
    )
    _grant("claude", tmp_path, checkpoint=True)

    same_mode = preview_host_admission(
        "claude",
        tmp_path,
        HostAdmissionAction.GRANT,
        route_profile="policy",
        grant_permits=True,
        owner="plugin",
        checkpoint=True,
    )
    assert same_mode.action is HostAdmissionAction.NOOP
    assert same_mode.files_after == {}

    moved = _grant("claude", tmp_path)
    assert moved.action is HostAdmissionAction.GRANT
    assert json.loads(settings.read_text(encoding="utf-8")) == {
        "permissions": {
            "allow": ["Bash(git status)", CLAUDE_CHECK_TOOL_NAME],
            "ask": ["WebFetch"],
        },
        "env": {"FOO": "1"},
    }


def test_claude_mode_change_apply_refuses_a_file_changed_after_preview(tmp_path: Path) -> None:
    """The mode change rides the same digest-bound preimage recheck as any other write."""

    settings = tmp_path / ".claude" / "settings.local.json"
    _grant("claude", tmp_path)
    preview = preview_host_admission(
        "claude",
        tmp_path,
        HostAdmissionAction.GRANT,
        route_profile="policy",
        grant_permits=True,
        owner="plugin",
        checkpoint=True,
    )
    assert preview.action is HostAdmissionAction.GRANT
    settings.write_text(json.dumps({"permissions": {"allow": ["Bash(ls)"]}}), encoding="utf-8")

    with pytest.raises(HostAdmissionError) as failure:
        apply_host_admission(preview, tmp_path, accepted_preview_digest=preview.preview_digest)
    assert failure.value.reason is HostAdmissionReason.PREVIEW_STALE
    assert json.loads(settings.read_text(encoding="utf-8")) == {
        "permissions": {"allow": ["Bash(ls)"]}
    }


@pytest.mark.parametrize(
    ("permissions", "detail"),
    [
        ({"deny": [CLAUDE_CHECK_TOOL_NAME]}, "deny_rule_present"),
        ({"deny": ["mcp__plugin_finishup_finishup__*"]}, "deny_rule_present"),
        ({"allow": ["mcp__plugin_finishup_finishup__*"]}, "wider_rule_present"),
        ({"allow": ["mcp__plugin_finishup_finishup"]}, "wider_rule_present"),
        (
            {"allow": [CLAUDE_CHECK_TOOL_NAME], "ask": [CLAUDE_CHECK_TOOL_NAME]},
            "allow_and_ask_present",
        ),
    ],
)
def test_claude_foreign_rules_are_reported_and_never_edited(
    tmp_path: Path, permissions: dict[str, list[str]], detail: str
) -> None:
    settings = tmp_path / ".claude" / "settings.local.json"
    settings.parent.mkdir()
    original = json.dumps({"permissions": permissions}).encode("utf-8")
    settings.write_bytes(original)

    observation = observe_host_admission("claude", tmp_path)
    assert observation.state is HostAdmissionState.FOREIGN
    assert observation.entries[0].detail == detail
    with pytest.raises(HostAdmissionError) as failure:
        preview_host_admission(
            "claude",
            tmp_path,
            HostAdmissionAction.GRANT,
            route_profile="policy",
            grant_permits=True,
            owner="plugin",
        )
    assert failure.value.reason is HostAdmissionReason.FOREIGN_ENTRY_PRESENT
    # Revoke likewise leaves a foreign rule alone: nothing to remove, file untouched.
    revoke = preview_host_admission(
        "claude", tmp_path, HostAdmissionAction.REVOKE, route_profile=None, grant_permits=None
    )
    assert revoke.action is HostAdmissionAction.NOOP
    assert "foreign_entry_retained" in revoke.warnings
    assert settings.read_bytes() == original


@pytest.mark.parametrize(
    ("content", "detail"),
    [
        (b"{not json", "file_invalid"),
        (b"[]", "shape_invalid"),
        (b'{"permissions": null}', "shape_invalid"),
        (b'{"permissions": {"allow": null}}', "shape_invalid"),
        (b'{"permissions": {"allow": "Bash"}}', "shape_invalid"),
        (b'{"permissions": []}', "shape_invalid"),
    ],
)
def test_an_unreadable_host_file_is_unknown_never_absent(
    tmp_path: Path, content: bytes, detail: str
) -> None:
    settings = tmp_path / ".claude" / "settings.local.json"
    settings.parent.mkdir()
    settings.write_bytes(content)
    observation = observe_host_admission("claude", tmp_path)
    assert observation.state is HostAdmissionState.UNKNOWN
    assert observation.observed is False
    assert observation.entries[0].detail == detail
    for action in (HostAdmissionAction.GRANT, HostAdmissionAction.REVOKE):
        with pytest.raises(HostAdmissionError) as failure:
            preview_host_admission(
                "claude",
                tmp_path,
                action,
                route_profile="policy",
                grant_permits=True,
                owner="plugin",
            )
        assert failure.value.reason is HostAdmissionReason.ENTRY_UNREADABLE
    assert settings.read_bytes() == content


def test_a_symlinked_host_file_is_unknown_and_never_followed(tmp_path: Path) -> None:
    real = tmp_path / "elsewhere.json"
    real.write_text(json.dumps({"permissions": {"allow": []}}), encoding="utf-8")
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.local.json").symlink_to(real)
    observation = observe_host_admission("claude", tmp_path)
    assert observation.state is HostAdmissionState.UNKNOWN
    assert observation.entries[0].detail == "file_symlink"


def test_a_symlinked_host_parent_is_unknown_and_revoke_never_deletes_through_it(
    tmp_path: Path,
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    settings = outside / "settings.local.json"
    original = json.dumps({"permissions": {"allow": [CLAUDE_PLUGIN_CHECK_TOOL_NAME]}}).encode(
        "utf-8"
    )
    settings.write_bytes(original)
    (tmp_path / ".claude").symlink_to(outside, target_is_directory=True)

    observation = observe_host_admission("claude", tmp_path)
    assert observation.state is HostAdmissionState.UNKNOWN
    assert observation.entries[0].detail == "file_symlink"
    with pytest.raises(HostAdmissionError) as failure:
        preview_host_admission(
            "claude",
            tmp_path,
            HostAdmissionAction.REVOKE,
            route_profile=None,
            grant_permits=None,
        )
    assert failure.value.reason is HostAdmissionReason.ENTRY_UNREADABLE
    assert settings.read_bytes() == original


# --- Codex --------------------------------------------------------------------------------


def test_codex_grant_appends_the_owner_form_table_and_revoke_strips_only_it(
    tmp_path: Path,
) -> None:
    config = tmp_path / ".codex" / "config.toml"
    config.parent.mkdir()
    owner_toml = b'model = "gpt-5.4"\n\n[mcp_servers.other]\ncommand = "other"\n'
    config.write_bytes(owner_toml)

    result = _grant("codex", tmp_path, owner="external")

    assert result.state_after is HostAdmissionState.PRESENT
    written = config.read_bytes()
    assert written == owner_toml + b"\n" + CODEX_EXTERNAL_ADMISSION_TABLE.encode("utf-8")
    parsed = tomllib.loads(written.decode("utf-8"))
    assert parsed["mcp_servers"]["finishup"]["tools"]["check"]["approval_mode"] == "approve"
    assert parsed["mcp_servers"]["other"] == {"command": "other"}
    assert observe_host_admission("codex", tmp_path, owner="external").entries[0].detail == (
        "external"
    )

    _revoke("codex", tmp_path, owner="external")
    assert config.read_bytes() == owner_toml


def test_codex_plugin_owner_uses_the_plugin_form_and_a_file_it_created_is_removed(
    tmp_path: Path,
) -> None:
    result = _grant("codex", tmp_path, owner="plugin")
    config = tmp_path / ".codex" / "config.toml"
    assert result.state_after is HostAdmissionState.PRESENT
    assert config.read_bytes() == CODEX_PLUGIN_ADMISSION_TABLE.encode("utf-8")
    parsed = tomllib.loads(config.read_text(encoding="utf-8"))
    assert parsed["plugins"]["finishup@finishup"]["mcp_servers"]["finishup"]["tools"]["check"] == {
        "approval_mode": "approve"
    }
    # Observed without an owner, the plugin form still reads as FinishUP's own entry.
    assert observe_host_admission("codex", tmp_path).entries[0].detail == "plugin"
    _revoke("codex", tmp_path, owner="plugin")
    assert not config.exists()


def test_codex_grant_adds_the_active_owner_form_when_only_the_inactive_form_exists(
    tmp_path: Path,
) -> None:
    config = tmp_path / ".codex" / "config.toml"
    config.parent.mkdir()
    config.write_bytes(CODEX_PLUGIN_ADMISSION_TABLE.encode("utf-8"))

    inactive = observe_host_admission("codex", tmp_path, owner="external")
    assert inactive.state is HostAdmissionState.ABSENT
    assert inactive.entries[0].detail == "inactive_plugin_entry_present"
    result = _grant("codex", tmp_path, owner="external")

    assert result.action is HostAdmissionAction.GRANT
    parsed = tomllib.loads(config.read_text(encoding="utf-8"))
    assert parsed["mcp_servers"]["finishup"]["tools"]["check"] == {"approval_mode": "approve"}
    assert parsed["plugins"]["finishup@finishup"]["mcp_servers"]["finishup"]["tools"]["check"] == {
        "approval_mode": "approve"
    }
    assert observe_host_admission("codex", tmp_path, owner="external").state is (
        HostAdmissionState.PRESENT
    )


@pytest.mark.parametrize(
    ("content", "detail"),
    [
        (b'[mcp_servers.finishup.tools.check]\napproval_mode = "prompt"\n', "entry_not_exact"),
        (
            b'[mcp_servers.finishup.tools.check]\napproval_mode = "approve"\noutput_token_limit = 4\n',
            "entry_not_exact",
        ),
        (
            b'[mcp_servers.finishup]\ndefault_tools_approval_mode = "approve"\n',
            "server_default_present",
        ),
    ],
)
def test_codex_non_exact_or_wider_tables_are_foreign_and_untouched(
    tmp_path: Path, content: bytes, detail: str
) -> None:
    config = tmp_path / ".codex" / "config.toml"
    config.parent.mkdir()
    config.write_bytes(content)
    observation = observe_host_admission("codex", tmp_path, owner="external")
    assert observation.state is HostAdmissionState.FOREIGN
    assert observation.entries[0].detail == detail
    with pytest.raises(HostAdmissionError):
        preview_host_admission(
            "codex",
            tmp_path,
            HostAdmissionAction.GRANT,
            route_profile="policy",
            grant_permits=True,
            owner="external",
        )
    assert sweep_host_admission(tmp_path, ("codex",))[0].outcome == "retained_foreign"
    assert config.read_bytes() == content


def test_codex_invalid_toml_is_unknown(tmp_path: Path) -> None:
    config = tmp_path / ".codex" / "config.toml"
    config.parent.mkdir()
    config.write_bytes(b"[mcp_servers\n")
    observation = observe_host_admission("codex", tmp_path)
    assert observation.state is HostAdmissionState.UNKNOWN
    assert observation.entries[0].detail == "file_invalid"
    assert sweep_host_admission(tmp_path, ("codex",))[0].outcome == "unknown"


def test_codex_grant_refuses_when_the_appended_table_would_not_parse(tmp_path: Path) -> None:
    """An inline ``mcp_servers = {}`` makes the header a re-declaration; never write that."""

    config = tmp_path / ".codex" / "config.toml"
    config.parent.mkdir()
    config.write_bytes(b"mcp_servers = {}\n")
    with pytest.raises(HostAdmissionError) as failure:
        preview_host_admission(
            "codex",
            tmp_path,
            HostAdmissionAction.GRANT,
            route_profile="policy",
            grant_permits=True,
            owner="external",
        )
    assert failure.value.reason is HostAdmissionReason.FOREIGN_ENTRY_PRESENT
    assert config.read_bytes() == b"mcp_servers = {}\n"


# --- Cursor -------------------------------------------------------------------------------


def test_cursor_grant_writes_both_surfaces_for_the_observed_owner(tmp_path: Path) -> None:
    result = _grant("cursor", tmp_path, owner="plugin")
    assert result.state_after is HostAdmissionState.PRESENT
    assert result.surfaces_changed == (".cursor/cli.json", ".cursor/permissions.json")
    ide = json.loads((tmp_path / ".cursor" / "permissions.json").read_text(encoding="utf-8"))
    cli = json.loads((tmp_path / ".cursor" / "cli.json").read_text(encoding="utf-8"))
    assert ide == {"mcpAllowlist": [CURSOR_IDE_ENTRY]}
    assert cli == {"permissions": {"allow": [CURSOR_CLI_PLUGIN_ENTRY]}}
    _revoke("cursor", tmp_path, owner="plugin")
    assert not (tmp_path / ".cursor" / "permissions.json").exists()
    assert not (tmp_path / ".cursor" / "cli.json").exists()


def test_cursor_partial_state_names_the_missing_surface_and_grant_completes_it(
    tmp_path: Path,
) -> None:
    ide = tmp_path / ".cursor" / "permissions.json"
    ide.parent.mkdir()
    # Case-insensitive host matching: an owner-spelled entry still counts as present.
    ide.write_text(json.dumps({"mcpAllowlist": ["FINISHUP:CHECK", "github:*"]}), encoding="utf-8")
    observation = observe_host_admission("cursor", tmp_path, owner="external")
    assert observation.state is HostAdmissionState.PARTIAL
    assert [entry.state.value for entry in observation.entries] == ["present", "absent"]

    result = _grant("cursor", tmp_path, owner="external")
    assert result.surfaces_changed == (".cursor/cli.json",)
    assert json.loads(ide.read_text(encoding="utf-8")) == {
        "mcpAllowlist": ["FINISHUP:CHECK", "github:*"]
    }
    assert result.state_after is HostAdmissionState.PRESENT


@pytest.mark.parametrize(
    ("surface", "content", "detail"),
    [
        (".cursor/permissions.json", {"mcpAllowlist": ["finishup:*"]}, "wider_rule_present"),
        (".cursor/permissions.json", {"mcpAllowlist": ["*:*"]}, "wider_rule_present"),
        (
            ".cursor/cli.json",
            {"permissions": {"deny": ["Mcp(finishup:check)"]}},
            "deny_rule_present",
        ),
        (".cursor/cli.json", {"permissions": {"allow": ["Mcp(*:*)"]}}, "wider_rule_present"),
    ],
)
def test_cursor_wider_or_deny_rules_are_foreign(
    tmp_path: Path, surface: str, content: dict[str, object], detail: str
) -> None:
    path = tmp_path / surface
    path.parent.mkdir()
    path.write_text(json.dumps(content), encoding="utf-8")
    observation = observe_host_admission("cursor", tmp_path, owner="external")
    assert observation.state is HostAdmissionState.FOREIGN
    foreign = next(entry for entry in observation.entries if entry.surface == surface)
    assert foreign.detail == detail


@pytest.mark.parametrize(
    ("surface", "content"),
    [
        (".cursor/permissions.json", {"mcpAllowlist": None}),
        (".cursor/cli.json", {"permissions": None}),
        (".cursor/cli.json", {"permissions": {"allow": None}}),
    ],
)
def test_cursor_null_shapes_are_unknown_never_absent(
    tmp_path: Path, surface: str, content: dict[str, object]
) -> None:
    path = tmp_path / surface
    path.parent.mkdir()
    path.write_text(json.dumps(content), encoding="utf-8")
    observation = observe_host_admission("cursor", tmp_path, owner="external")
    assert observation.state is HostAdmissionState.UNKNOWN
    entry = next(item for item in observation.entries if item.surface == surface)
    assert entry.detail == "shape_invalid"


# --- digest binding and sweeps --------------------------------------------------------------


def test_apply_refuses_a_stale_digest_and_a_file_changed_after_preview(tmp_path: Path) -> None:
    preview = preview_host_admission(
        "claude",
        tmp_path,
        HostAdmissionAction.GRANT,
        route_profile="policy",
        grant_permits=True,
        owner="plugin",
    )
    with pytest.raises(HostAdmissionError) as failure:
        apply_host_admission(preview, tmp_path, accepted_preview_digest="sha256:" + "0" * 64)
    assert failure.value.reason is HostAdmissionReason.PREVIEW_STALE

    # The host file changes underneath the accepted preview: the bound bytes no longer match.
    settings = tmp_path / ".claude" / "settings.local.json"
    settings.parent.mkdir()
    settings.write_text(json.dumps({"permissions": {"allow": ["Bash(ls)"]}}), encoding="utf-8")
    with pytest.raises(HostAdmissionError) as stale:
        apply_host_admission(preview, tmp_path, accepted_preview_digest=preview.preview_digest)
    assert stale.value.reason is HostAdmissionReason.PREVIEW_STALE
    assert json.loads(settings.read_text(encoding="utf-8")) == {
        "permissions": {"allow": ["Bash(ls)"]}
    }


def test_apply_rechecks_bytes_immediately_before_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = tmp_path / ".claude" / "settings.local.json"
    settings.parent.mkdir()
    settings.write_text(json.dumps({"permissions": {"allow": ["Bash(ls)"]}}))
    preview = preview_host_admission(
        "claude",
        tmp_path,
        HostAdmissionAction.GRANT,
        route_profile="policy",
        grant_permits=True,
        owner="plugin",
    )
    original_mutator = module._delete_or_write  # pyright: ignore[reportPrivateUsage]

    def mutate_then_apply(path: Path, payload: bytes, *, expected_digest: str | None) -> None:
        settings.write_text(json.dumps({"permissions": {"allow": ["Bash(git status)"]}}))
        original_mutator(path, payload, expected_digest=expected_digest)

    monkeypatch.setattr(module, "_delete_or_write", mutate_then_apply)
    with pytest.raises(HostAdmissionError) as failure:
        apply_host_admission(preview, tmp_path, accepted_preview_digest=preview.preview_digest)

    assert failure.value.reason is HostAdmissionReason.PREVIEW_STALE
    assert json.loads(settings.read_text()) == {"permissions": {"allow": ["Bash(git status)"]}}


def test_cursor_second_surface_drift_after_first_mutation_reports_write_failed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    preview = preview_host_admission(
        "cursor",
        tmp_path,
        HostAdmissionAction.GRANT,
        route_profile="policy",
        grant_permits=True,
        owner="external",
    )
    original_mutator = module._delete_or_write  # pyright: ignore[reportPrivateUsage]

    def drift_second_surface(path: Path, payload: bytes, *, expected_digest: str | None) -> None:
        if path.name == "permissions.json":
            path.parent.mkdir(exist_ok=True)
            path.write_text(json.dumps({"mcpAllowlist": ["github:search"]}))
        original_mutator(path, payload, expected_digest=expected_digest)

    monkeypatch.setattr(module, "_delete_or_write", drift_second_surface)
    with pytest.raises(HostAdmissionError) as failure:
        apply_host_admission(preview, tmp_path, accepted_preview_digest=preview.preview_digest)

    assert failure.value.reason is HostAdmissionReason.WRITE_FAILED
    assert (tmp_path / ".cursor" / "cli.json").exists()
    assert json.loads((tmp_path / ".cursor" / "permissions.json").read_text()) == {
        "mcpAllowlist": ["github:search"]
    }


def test_noop_apply_rechecks_the_accepted_state(tmp_path: Path) -> None:
    _grant("claude", tmp_path)
    preview = preview_host_admission(
        "claude",
        tmp_path,
        HostAdmissionAction.GRANT,
        route_profile="policy",
        grant_permits=True,
        owner="plugin",
    )
    assert preview.action is HostAdmissionAction.NOOP
    (tmp_path / ".claude" / "settings.local.json").unlink()

    with pytest.raises(HostAdmissionError) as failure:
        apply_host_admission(preview, tmp_path, accepted_preview_digest=preview.preview_digest)
    assert failure.value.reason is HostAdmissionReason.PREVIEW_STALE


def test_preview_digest_binds_host_action_owner_and_checkpoint(tmp_path: Path) -> None:
    def digest(**kwargs: object) -> str:
        host = kwargs.pop("host", "claude")
        if host == "claude" and "owner" not in kwargs:
            kwargs["owner"] = "plugin"
        return preview_host_admission(
            host,  # type: ignore[arg-type]
            tmp_path,
            HostAdmissionAction.GRANT,
            route_profile="policy",
            grant_permits=True,
            **kwargs,  # type: ignore[arg-type]
        ).preview_digest

    assert digest() != digest(checkpoint=True)
    assert digest(host="codex", owner="external") != digest(host="codex", owner="plugin")
    assert digest(host="cursor", owner="external") != digest(host="cursor", owner="plugin")
    assert digest() == digest()


def test_sweep_removes_exactly_finishup_entries_across_hosts_and_reports_each(
    tmp_path: Path,
) -> None:
    _grant("claude", tmp_path)
    _grant("codex", tmp_path, owner="plugin")
    cursor_ide = tmp_path / ".cursor" / "permissions.json"
    cursor_ide.parent.mkdir()
    cursor_ide.write_text(json.dumps({"mcpAllowlist": ["finishup:*"]}), encoding="utf-8")

    outcomes = sweep_host_admission(tmp_path)

    assert [(item.host, item.outcome) for item in outcomes] == [
        ("claude", "removed"),
        ("codex", "removed"),
        ("cursor", "retained_foreign"),
    ]
    assert outcomes[0].surfaces_changed == (".claude/settings.local.json",)
    assert not (tmp_path / ".claude" / "settings.local.json").exists()
    assert not (tmp_path / ".codex" / "config.toml").exists()
    assert json.loads(cursor_ide.read_text(encoding="utf-8")) == {"mcpAllowlist": ["finishup:*"]}
    # A second sweep finds nothing of FinishUP's to remove.
    assert [item.outcome for item in sweep_host_admission(tmp_path)] == [
        "absent",
        "absent",
        "retained_foreign",
    ]


def test_sweep_with_no_owner_removes_both_codex_forms(tmp_path: Path) -> None:
    config = tmp_path / ".codex" / "config.toml"
    config.parent.mkdir()
    config.write_bytes(
        b'model = "x"\n\n'
        + CODEX_EXTERNAL_ADMISSION_TABLE.encode("utf-8")
        + b"\n"
        + CODEX_PLUGIN_ADMISSION_TABLE.encode("utf-8")
    )
    assert observe_host_admission("codex", tmp_path).entries[0].detail == "both"
    assert sweep_host_admission(tmp_path, ("codex",))[0].outcome == "removed"
    assert config.read_bytes() == b'model = "x"\n'


def test_revoke_removes_every_exact_claude_owner_form(tmp_path: Path) -> None:
    settings = tmp_path / ".claude" / "settings.local.json"
    settings.parent.mkdir()
    settings.write_text(
        json.dumps(
            {
                "permissions": {
                    "allow": [CLAUDE_EXTERNAL_CHECK_TOOL_NAME],
                    "ask": [CLAUDE_PLUGIN_CHECK_TOOL_NAME],
                }
            }
        )
    )
    result = _revoke("claude", tmp_path, owner="external")
    assert result.state_after is HostAdmissionState.ABSENT
    assert not settings.exists()


def test_relative_or_missing_project_root_is_unsafe(tmp_path: Path) -> None:
    with pytest.raises(HostAdmissionError) as failure:
        observe_host_admission("claude", Path("relative"))
    assert failure.value.reason is HostAdmissionReason.TARGET_UNSAFE
    with pytest.raises(HostAdmissionError):
        observe_host_admission("claude", tmp_path / "missing")


def test_errors_and_reports_never_carry_paths_or_contents(tmp_path: Path) -> None:
    settings = tmp_path / ".claude" / "settings.local.json"
    settings.parent.mkdir()
    settings.write_text(json.dumps({"permissions": {"allow": ["Bash(SECRET_CANARY)"]}}))
    observation = observe_host_admission("claude", tmp_path)
    rendered = json.dumps(observation.as_json())
    assert "SECRET_CANARY" not in rendered
    assert str(tmp_path) not in rendered
    preview = preview_host_admission(
        "claude",
        tmp_path,
        HostAdmissionAction.GRANT,
        route_profile="policy",
        grant_permits=True,
        owner="plugin",
    )
    rendered = json.dumps(preview.as_json())
    assert "SECRET_CANARY" not in rendered
    assert str(tmp_path) not in rendered


# --- legacy ``yoetz`` server-name entries (ADR-048) ----------------------------------------


def _write_json(path: Path, body: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(body, indent=2) + "\n", encoding="utf-8")


def test_legacy_entries_are_reported_without_changing_the_state(tmp_path: Path) -> None:
    _write_json(
        tmp_path / ".claude/settings.local.json",
        {"permissions": {"allow": ["mcp__yoetz__check", "Bash(ls)"]}},
    )
    (tmp_path / ".codex").mkdir()
    (tmp_path / ".codex/config.toml").write_text(
        '[mcp_servers.yoetz.tools.check]\napproval_mode = "approve"\n', encoding="utf-8"
    )
    _write_json(tmp_path / ".cursor/permissions.json", {"mcpAllowlist": ["Yoetz:Check"]})
    _write_json(
        tmp_path / ".cursor/cli.json", {"permissions": {"allow": ["Mcp(plugin-yoetz-yoetz:check)"]}}
    )

    claude = observe_host_admission("claude", tmp_path)
    assert claude.state is HostAdmissionState.ABSENT
    assert claude.entries[0].legacy_entries == ("mcp__yoetz__check",)
    assert claude.as_json()["legacy_entries_present"] is True
    codex = observe_host_admission("codex", tmp_path)
    assert codex.state is HostAdmissionState.ABSENT
    assert codex.entries[0].legacy_entries == ("[mcp_servers.yoetz.tools.check]",)
    cursor = observe_host_admission("cursor", tmp_path)
    assert [entry.legacy_entries for entry in cursor.entries] == [
        ("Yoetz:Check",),
        ("Mcp(plugin-yoetz-yoetz:check)",),
    ]
    assert observe_host_admission("claude", tmp_path / ".codex").legacy_entries_present is False


def test_grant_writes_only_the_finishup_name_and_keeps_legacy_entries(tmp_path: Path) -> None:
    _write_json(
        tmp_path / ".claude/settings.local.json",
        {"permissions": {"allow": ["mcp__plugin_yoetz_yoetz__check"]}},
    )
    _grant("claude", tmp_path)
    allow = json.loads((tmp_path / ".claude/settings.local.json").read_text())["permissions"][
        "allow"
    ]
    assert allow == ["mcp__plugin_yoetz_yoetz__check", CLAUDE_PLUGIN_CHECK_TOOL_NAME]
    assert not any("yoetz" in entry for entry in allow[1:])


def test_revoke_removes_legacy_entries_on_every_host(tmp_path: Path) -> None:
    _write_json(
        tmp_path / ".claude/settings.local.json",
        {"permissions": {"allow": ["Bash(ls)"], "ask": ["mcp__yoetz__check"]}},
    )
    (tmp_path / ".codex").mkdir()
    (tmp_path / ".codex/config.toml").write_text(
        'model = "gpt-5"\n\n'
        '[plugins."yoetz@yoetz".mcp_servers.yoetz.tools.check]\napproval_mode = "approve"\n',
        encoding="utf-8",
    )
    _write_json(tmp_path / ".cursor/permissions.json", {"mcpAllowlist": ["yoetz:check"]})
    _grant("cursor", tmp_path, owner="external")
    _write_json(
        tmp_path / ".cursor/cli.json",
        {"permissions": {"allow": ["Mcp(finishup:check)", "Mcp(yoetz:check)"]}},
    )

    claude = preview_host_admission(
        "claude", tmp_path, HostAdmissionAction.REVOKE, route_profile=None, grant_permits=None
    )
    assert claude.action is HostAdmissionAction.REVOKE
    assert "legacy_entries_removed" in claude.warnings
    _revoke("claude", tmp_path)
    _revoke("codex", tmp_path)
    _revoke("cursor", tmp_path)

    settings = json.loads((tmp_path / ".claude/settings.local.json").read_text())
    assert settings == {"permissions": {"allow": ["Bash(ls)"]}}
    assert (tmp_path / ".codex/config.toml").read_text(encoding="utf-8") == 'model = "gpt-5"\n'
    assert not (tmp_path / ".cursor/permissions.json").exists()
    assert not (tmp_path / ".cursor/cli.json").exists()
    for host in ("claude", "codex", "cursor"):
        assert observe_host_admission(host, tmp_path).legacy_entries_present is False


def test_sweep_removes_a_legacy_only_entry(tmp_path: Path) -> None:
    (tmp_path / ".codex").mkdir()
    (tmp_path / ".codex/config.toml").write_text(
        '[mcp_servers.yoetz.tools.check]\napproval_mode = "approve"\n', encoding="utf-8"
    )
    (outcome,) = sweep_host_admission(tmp_path, ("codex",))
    assert outcome.outcome == "removed"
    assert not (tmp_path / ".codex/config.toml").exists()


def test_a_non_exact_legacy_table_is_not_ours_and_stays(tmp_path: Path) -> None:
    (tmp_path / ".codex").mkdir()
    text = '[mcp_servers.yoetz.tools.check]\napproval_mode = "approve"\nnote = "owner"\n'
    (tmp_path / ".codex/config.toml").write_text(text, encoding="utf-8")
    assert observe_host_admission("codex", tmp_path).legacy_entries_present is False
    (outcome,) = sweep_host_admission(tmp_path, ("codex",))
    assert outcome.outcome == "absent"
    assert (tmp_path / ".codex/config.toml").read_text(encoding="utf-8") == text


def _legacy_grants_on_every_host(root: Path) -> None:
    _write_json(
        root / ".claude/settings.local.json",
        {"permissions": {"allow": ["Bash(ls)", "mcp__yoetz__check"], "ask": ["mcp__yoetz__check"]}},
    )
    (root / ".codex").mkdir(exist_ok=True)
    (root / ".codex/config.toml").write_text(
        'model = "gpt-5"\n\n[mcp_servers.yoetz.tools.check]\napproval_mode = "approve"\n',
        encoding="utf-8",
    )
    _write_json(root / ".cursor/permissions.json", {"mcpAllowlist": ["yoetz:check"]})
    _write_json(root / ".cursor/cli.json", {"permissions": {"allow": ["Mcp(yoetz:check)"]}})


def test_grant_retires_stale_legacy_entries_without_revoking_the_grant(tmp_path: Path) -> None:
    """No FinishUP registration uses the old name: grant removes the stale entries (ADR-048)."""

    _legacy_grants_on_every_host(tmp_path)
    for host in ("claude", "codex", "cursor"):
        preview = preview_host_admission(
            host,
            tmp_path,
            HostAdmissionAction.GRANT,
            route_profile="policy",
            grant_permits=True,
            owner="external",
            legacy_name="unused",
        )
        assert "legacy_entries_removed" in preview.warnings
        apply_host_admission(preview, tmp_path, accepted_preview_digest=preview.preview_digest)
        after = observe_host_admission(host, tmp_path, owner="external")
        assert after.state is HostAdmissionState.PRESENT
        assert after.legacy_entries_present is False

    settings = json.loads((tmp_path / ".claude/settings.local.json").read_text())
    assert settings["permissions"]["allow"] == ["Bash(ls)", CLAUDE_EXTERNAL_CHECK_TOOL_NAME]
    assert "ask" not in settings["permissions"]
    codex = (tmp_path / ".codex/config.toml").read_text(encoding="utf-8")
    assert codex.startswith('model = "gpt-5"\n')
    assert "yoetz" not in codex and CODEX_EXTERNAL_ADMISSION_TABLE in codex


def test_grant_over_a_present_entry_retires_only_the_legacy_one(tmp_path: Path) -> None:
    _grant("codex", tmp_path, owner="external")
    config = tmp_path / ".codex/config.toml"
    config.write_text(
        config.read_text(encoding="utf-8")
        + '\n[mcp_servers.yoetz.tools.check]\napproval_mode = "approve"\n',
        encoding="utf-8",
    )
    kept = preview_host_admission(
        "codex",
        tmp_path,
        HostAdmissionAction.GRANT,
        route_profile="policy",
        grant_permits=True,
        owner="external",
    )
    # Unread legacy use: the grant is already in place and the legacy entry stays.
    assert kept.action is HostAdmissionAction.NOOP
    assert "legacy_entries_retained" in kept.warnings

    result = _grant("codex", tmp_path, owner="external", legacy_name="unused")

    assert result.action is HostAdmissionAction.GRANT
    assert result.state_after is HostAdmissionState.PRESENT
    assert config.read_text(encoding="utf-8").count("[mcp_servers.") == 1
    assert observe_host_admission("codex", tmp_path).legacy_entries_present is False


@pytest.mark.parametrize("legacy_name", [None, "shared"])
def test_grant_keeps_legacy_entries_a_registration_still_uses(
    tmp_path: Path, legacy_name: str | None
) -> None:
    _write_json(tmp_path / ".cursor/permissions.json", {"mcpAllowlist": ["yoetz:check"]})
    preview = preview_host_admission(
        "cursor",
        tmp_path,
        HostAdmissionAction.GRANT,
        route_profile="policy",
        grant_permits=True,
        owner="external",
        legacy_name=legacy_name,  # type: ignore[arg-type]
    )
    assert "legacy_entries_retained" in preview.warnings
    apply_host_admission(preview, tmp_path, accepted_preview_digest=preview.preview_digest)
    allow = json.loads((tmp_path / ".cursor/permissions.json").read_text())["mcpAllowlist"]
    assert allow == ["yoetz:check", CURSOR_IDE_ENTRY]


def test_grant_refuses_while_the_host_serves_only_the_legacy_name(tmp_path: Path) -> None:
    for host in ("claude", "codex", "cursor"):
        with pytest.raises(HostAdmissionError) as caught:
            preview_host_admission(
                host,
                tmp_path,
                HostAdmissionAction.GRANT,
                route_profile="policy",
                grant_permits=True,
                owner="external",
                legacy_name="serving",
            )
        assert caught.value.reason is HostAdmissionReason.LEGACY_REGISTRATION_ACTIVE
    assert not (tmp_path / ".codex").exists()
    # The way out stays open whatever the legacy use.
    revoke = preview_host_admission(
        "codex",
        tmp_path,
        HostAdmissionAction.REVOKE,
        route_profile=None,
        grant_permits=None,
        legacy_name="serving",
    )
    assert revoke.action is HostAdmissionAction.NOOP


def test_the_observed_legacy_use_is_bound_into_the_preview_digest(tmp_path: Path) -> None:
    _legacy_grants_on_every_host(tmp_path)
    digests = {
        legacy_name: preview_host_admission(
            "codex",
            tmp_path,
            HostAdmissionAction.GRANT,
            route_profile="policy",
            grant_permits=True,
            owner="external",
            legacy_name=legacy_name,  # type: ignore[arg-type]
        ).preview_digest
        for legacy_name in (None, "shared", "unused")
    }
    assert len(set(digests.values())) == 3
    with pytest.raises(HostAdmissionError) as caught:
        preview_host_admission(
            "codex",
            tmp_path,
            HostAdmissionAction.GRANT,
            route_profile="policy",
            grant_permits=True,
            owner="external",
            legacy_name="maybe",  # type: ignore[arg-type]
        )
    assert caught.value.reason is HostAdmissionReason.HOST_INVALID
