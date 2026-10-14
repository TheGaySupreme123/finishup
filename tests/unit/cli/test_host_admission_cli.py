"""``finishup integrate <host> admission`` (issue #467): the CLI gate over the adapter.

The adapter decides; these tests pin that the CLI hands it observed facts and nothing invented —
an unread grant or route is ``None`` and refuses a grant — and that the JSON surfaces stay
path-free.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest
from typer.testing import CliRunner

from finishup.cli import host_admission as module
from finishup.cli.app import app


def _facts(
    *,
    route: str | None = "policy",
    owner: str | None = "plugin",
    grant: str | None = "granted",
    llm: bool | None = True,
) -> module.AdmissionFacts:
    return module.AdmissionFacts(
        route_profile=route,
        owner=cast("module.McpOwnerForm | None", owner),
        route_observed=route is not None,
        grant_state=grant,
        llm_inference_enabled=llm,
        service_state="ready",
    )


def _stub_facts(monkeypatch: pytest.MonkeyPatch, facts: module.AdmissionFacts) -> None:
    async def gather(*_args: object, **_kwargs: object) -> module.AdmissionFacts:
        return facts

    monkeypatch.setattr(module, "gather_admission_facts", gather)


def _run(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, *args: str) -> tuple[int, str, str]:
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["integrate", *args, "--project-root", str(tmp_path), "--json"],
    )
    return result.exit_code, result.stdout, result.stderr


def test_preview_grant_and_revoke_round_trip_through_the_cli(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _stub_facts(monkeypatch, _facts())
    code, out, _err = _run(monkeypatch, tmp_path, "claude", "admission", "preview")
    assert code == 0, out
    preview = json.loads(out)
    assert preview["action"] == "grant"
    assert preview["state_before"] == "absent"
    assert preview["route"] == {"observed": True, "owner": "plugin", "route_profile": "policy"}
    assert preview["grant"]["permits_external_review"] is True
    assert preview["surfaces_changed"] == [".claude/settings.local.json"]
    assert "host_config_not_compare_and_swap" in preview["warnings"]
    assert "claude_local_settings_held_until_trusted_when_tracked" in preview["warnings"]
    assert str(tmp_path) not in out

    code, out, err = _run(monkeypatch, tmp_path, "claude", "admission", "grant", "--accept")
    assert code == 3
    assert "host_admission_exact_preview_acceptance_required" in err
    assert not (tmp_path / ".claude").exists()

    code, out, _err = _run(
        monkeypatch,
        tmp_path,
        "claude",
        "admission",
        "grant",
        "--accept",
        "--preview-digest",
        preview["preview_digest"],
    )
    assert code == 0, out
    granted = json.loads(out)
    assert granted["state_after"] == "present"
    assert json.loads((tmp_path / ".claude" / "settings.local.json").read_text()) == {
        "permissions": {"allow": ["mcp__plugin_finishup_finishup__check"]}
    }

    code, out, _err = _run(monkeypatch, tmp_path, "claude", "admission", "status")
    assert code == 0
    status = json.loads(out)
    assert status["admission"]["state"] == "present"
    assert status["admission"]["entries"][0]["detail"] == "allow"

    # Revoke works with every fact unread.
    _stub_facts(monkeypatch, _facts(route=None, owner=None, grant=None, llm=None))
    code, out, _err = _run(
        monkeypatch, tmp_path, "claude", "admission", "preview", "--action", "revoke"
    )
    assert code == 0, out
    revoke = json.loads(out)
    assert revoke["action"] == "revoke"
    code, out, _err = _run(
        monkeypatch,
        tmp_path,
        "claude",
        "admission",
        "revoke",
        "--accept",
        "--preview-digest",
        revoke["preview_digest"],
    )
    assert code == 0, out
    assert json.loads(out)["state_after"] == "absent"
    assert not (tmp_path / ".claude" / "settings.local.json").exists()


@pytest.mark.parametrize(
    ("facts", "reason"),
    [
        (_facts(route="strict"), "route_not_policy"),
        (_facts(route=None, owner=None), "route_unobserved"),
        (_facts(grant=None), "grant_unverifiable"),
        (_facts(grant="missing"), "grant_not_permitting"),
        (_facts(llm=False), "grant_not_permitting"),
    ],
)
def test_grant_preview_refuses_on_unread_or_non_permitting_facts(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    facts: module.AdmissionFacts,
    reason: str,
) -> None:
    _stub_facts(monkeypatch, facts)
    for host in ("claude", "codex", "cursor"):
        code, _out, err = _run(monkeypatch, tmp_path, host, "admission", "preview")
        assert code == 1
        assert f"host_admission_{reason}" in err
    assert sorted(tmp_path.iterdir()) == []


def test_codex_and_cursor_grants_follow_the_observed_owner(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _stub_facts(monkeypatch, _facts(owner="plugin"))
    for host in ("codex", "cursor"):
        code, out, _err = _run(monkeypatch, tmp_path, host, "admission", "preview")
        assert code == 0, out
        preview = json.loads(out)
        code, out, _err = _run(
            monkeypatch,
            tmp_path,
            host,
            "admission",
            "grant",
            "--accept",
            "--preview-digest",
            preview["preview_digest"],
        )
        assert code == 0, out
    assert (tmp_path / ".codex" / "config.toml").read_text(encoding="utf-8") == (
        '[plugins."finishup@finishup".mcp_servers.finishup.tools.check]\napproval_mode = "approve"\n'
    )
    assert json.loads((tmp_path / ".cursor" / "cli.json").read_text(encoding="utf-8")) == {
        "permissions": {"allow": ["Mcp(plugin-finishup-finishup:check)"]}
    }


def test_claude_external_registration_uses_its_configured_server_name(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _stub_facts(monkeypatch, _facts(owner="external"))
    code, out, _err = _run(monkeypatch, tmp_path, "claude", "admission", "preview")
    assert code == 0, out
    preview = json.loads(out)
    code, out, _err = _run(
        monkeypatch,
        tmp_path,
        "claude",
        "admission",
        "grant",
        "--accept",
        "--preview-digest",
        preview["preview_digest"],
    )
    assert code == 0, out
    settings = json.loads(
        (tmp_path / ".claude" / "settings.local.json").read_text(encoding="utf-8")
    )
    assert settings == {"permissions": {"allow": ["mcp__finishup__check"]}}


def test_status_reads_without_facts_and_reports_unknown_for_an_unreadable_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _stub_facts(monkeypatch, _facts(route=None, owner=None, grant=None, llm=None))
    (tmp_path / ".cursor").mkdir()
    (tmp_path / ".cursor" / "permissions.json").write_bytes(b"{broken")
    code, out, _err = _run(monkeypatch, tmp_path, "cursor", "admission", "status")
    assert code == 0, out
    status = json.loads(out)
    assert status["admission"]["state"] == "unknown"
    assert status["admission"]["observed"] is False
    assert status["grant"]["permits_external_review"] is None


@pytest.mark.anyio
async def test_gather_facts_maps_provider_status_for_codex_and_leaves_others_unobserved(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import finishup.cli.provider_status as provider_status

    async def report(*, workspace_locator: Path | None = None) -> dict[str, object]:
        assert workspace_locator == tmp_path
        return {
            "repository_grant_state": "granted",
            "llm_inference_enabled": True,
            "service_state": "ready",
            "mcp_route": {
                "observed": True,
                "registered_profile": "policy",
                "ownership_state": "external",
            },
        }

    monkeypatch.setattr(provider_status, "provider_status_report", report)
    codex = await module.gather_admission_facts("codex", tmp_path)
    assert codex.route_profile == "policy"
    assert codex.owner == "external"
    assert codex.grant_permits is True
    # Claude and Cursor need their explicit roots to observe a route; without them the route
    # is unread, so a grant cannot proceed on an assumed route.
    claude = await module.gather_admission_facts("claude", tmp_path)
    assert claude.route_profile is None and claude.route_observed is False
    cursor = await module.gather_admission_facts("cursor", tmp_path)
    assert cursor.route_profile is None and cursor.route_observed is False


def test_unknown_action_and_host_are_usage_errors(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _stub_facts(monkeypatch, _facts())
    code, _out, err = _run(
        monkeypatch, tmp_path, "claude", "admission", "preview", "--action", "widen"
    )
    assert code == 2
    assert "host_admission_action_invalid" in err
    code, _out, err = _run(monkeypatch, tmp_path, "vim", "admission", "status")
    assert code == 2
    assert "host_admission_command_invalid" in err


@pytest.mark.parametrize(
    ("failure", "expected"),
    [
        (FileNotFoundError("PRIVATE_PATH"), "host_admission_target_unsafe\n"),
        (RuntimeError("PRIVATE_PATH"), "host_admission_host_invalid\n"),
    ],
)
def test_raw_observation_errors_are_reduced_to_path_free_tokens(
    failure: Exception, expected: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    private_path = tmp_path / "owner-secret-project"
    failure.args = (str(private_path),)

    async def fail(*_args: object, **_kwargs: object) -> module.AdmissionFacts:
        raise failure

    monkeypatch.setattr(module, "gather_admission_facts", fail)
    code, _out, err = _run(monkeypatch, tmp_path, "claude", "admission", "preview")
    assert code == 1
    assert err == expected
    assert str(private_path) not in err


def test_reverse_sweep_and_its_preview_disclosure_touch_only_finishup_entries(
    tmp_path: Path,
) -> None:
    """The reverse transitions (uninstall, strict re-render, unregistration) ride on these."""

    settings = tmp_path / ".claude" / "settings.local.json"
    settings.parent.mkdir()
    settings.write_text(
        json.dumps(
            {"permissions": {"allow": ["Bash(git status)", "mcp__plugin_finishup_finishup__check"]}}
        ),
        encoding="utf-8",
    )
    disclosed = module.admission_cleanup_preview("claude", tmp_path)
    assert disclosed == {
        "host": "claude",
        "state": "present",
        "surfaces": [".claude/settings.local.json"],
    }
    swept = module.reverse_sweep("claude", tmp_path)
    assert swept == {
        "host": "claude",
        "outcome": "removed",
        "surfaces_changed": [".claude/settings.local.json"],
    }
    assert json.loads(settings.read_text(encoding="utf-8")) == {
        "permissions": {"allow": ["Bash(git status)"]}
    }
    assert module.reverse_sweep("claude", tmp_path)["outcome"] == "absent"
    assert module.admission_cleanup_preview("cursor", tmp_path)["state"] == "absent"
    assert module.admission_cleanup_preview("claude", tmp_path / "missing")["state"] == "unknown"
