"""``yoetz privacy credential-heuristic`` (issue #982 owner opt-out): the way in and the way out."""

from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

import yoetz.cli.privacy_setup as setup
from yoetz.application.privacy_policy import privacy_policy_changes
from yoetz.cli.app import app
from yoetz.domain.privacy import (
    AuthorizationScope,
    AuthorizationScopeKind,
    ChannelPolicy,
    CredentialHeuristic,
    DataClass,
    EgressChannel,
    PrivacyPolicy,
    PrivacyProfile,
    ReviewContextProfile,
    ReviewSelectionPolicy,
)
from yoetz.domain.values import JsonObject
from yoetz.protocol.models import DataCategory

_INSTALLATION = "ins_10000000-0000-4000-8000-000000000001"
_DIGEST = f"sha256:{'2' * 64}"
_AUTHORITY = f"sha256:{'3' * 64}"
_NOW = datetime(2026, 10, 7, tzinfo=UTC)


def _off(channel: EgressChannel) -> ChannelPolicy:
    return ChannelPolicy(
        channel, False, (), (), None, (), AuthorizationScopeKind.MACHINE, False, 0, 0, 0
    )


def _policy(setting: CredentialHeuristic = CredentialHeuristic.ENFORCED) -> PrivacyPolicy:
    return PrivacyPolicy(
        "pvy_10000000-0000-4000-8000-000000000004",
        3,
        _DIGEST,
        PrivacyProfile.LOCAL_ONLY,
        ReviewContextProfile.STRUCTURAL,
        ReviewSelectionPolicy.for_profile(ReviewContextProfile.STRUCTURAL),
        False,
        False,
        AuthorizationScope(AuthorizationScopeKind.MACHINE, _INSTALLATION),
        tuple(_off(channel) for channel in sorted(EgressChannel, key=lambda c: c.value)),
        False,
        None,
        (),
        (),
        (DataCategory.FINDING_SUMMARY,),
        (DataClass.ORDINARY_USER_CONTENT,),
        tuple(DataCategory),
        (DataClass.ORDINARY_USER_CONTENT,),
        _NOW,
        credential_heuristic=setting,
    )


def _snapshot(policy: PrivacyPolicy, grant: str = "granted") -> setup.PrivacySetupSnapshot:
    return setup.PrivacySetupSnapshot(
        policy,
        JsonObject({"kind": "machine", "installation_id": _INSTALLATION}),
        _AUTHORITY,
        grant,  # pyright: ignore[reportArgumentType]
        "not_applicable",
    )


def test_candidate_changes_only_the_heuristic_and_names_its_predecessor() -> None:
    current = _policy()
    candidate = setup.credential_heuristic_candidate(
        current, CredentialHeuristic.DISABLED, now=_NOW
    )
    assert candidate.credential_heuristic is CredentialHeuristic.DISABLED
    assert candidate.version == current.version + 1
    assert candidate.supersedes_policy_digest == current.policy_digest
    assert candidate.policy_digest != current.policy_digest
    changes = privacy_policy_changes(current, candidate)
    assert [(change.field, change.widens) for change in changes] == [("credential_heuristic", True)]


def test_disable_proposes_and_requires_the_trusted_decision(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proposed: list[PrivacyPolicy] = []
    decided: list[str] = []

    async def snapshot(_locator: object = None) -> setup.PrivacySetupSnapshot:
        return _snapshot(_policy())

    async def propose(candidate: PrivacyPolicy, digest: str, **_: object) -> str:
        assert digest == _AUTHORITY
        proposed.append(candidate)
        return "ppr_10000000-0000-4000-8000-000000000009"

    async def decide(proposal_id: str) -> object:
        decided.append(proposal_id)
        return SimpleNamespace(status="committed")

    monkeypatch.setattr(setup, "_interactive_terminal", lambda: True)
    monkeypatch.setattr(setup, "get_privacy_setup_snapshot", snapshot)
    monkeypatch.setattr(setup, "_propose", propose)
    monkeypatch.setattr(setup, "_decide", decide)
    report = asyncio.run(setup.run_credential_heuristic_change(CredentialHeuristic.DISABLED))
    assert report.outcome == "configured"
    assert [policy.credential_heuristic for policy in proposed] == [CredentialHeuristic.DISABLED]
    assert decided == ["ppr_10000000-0000-4000-8000-000000000009"]


def test_disable_declined_at_the_ceremony_changes_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def snapshot(_locator: object = None) -> setup.PrivacySetupSnapshot:
        return _snapshot(_policy())

    async def propose(*_: object, **__: object) -> str:
        return "ppr_10000000-0000-4000-8000-000000000009"

    async def decide(_proposal_id: str) -> object:
        return SimpleNamespace(status="denied")

    monkeypatch.setattr(setup, "_interactive_terminal", lambda: True)
    monkeypatch.setattr(setup, "get_privacy_setup_snapshot", snapshot)
    monkeypatch.setattr(setup, "_propose", propose)
    monkeypatch.setattr(setup, "_decide", decide)
    report = asyncio.run(setup.run_credential_heuristic_change(CredentialHeuristic.DISABLED))
    assert report.outcome == "cancelled"
    assert report.reason == "privacy_decision_not_approved"


def test_disable_needs_a_local_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(setup, "_interactive_terminal", lambda: False)
    report = asyncio.run(setup.run_credential_heuristic_change(CredentialHeuristic.DISABLED))
    assert (report.outcome, report.reason) == ("failed", "local_terminal_required")


def test_disable_without_a_grant_walks_the_grant_creation_ceremony(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Owner decision 2026-10-07: the opt-out becomes part of the grant the owner approves."""

    calls: list[dict[str, object]] = []

    async def snapshot(_locator: object = None) -> setup.PrivacySetupSnapshot:
        return _snapshot(_policy(), grant="missing")

    async def never(*_: object, **__: object) -> str:
        raise AssertionError("must not propose outside the grant-creation ceremony")

    async def run_setup(**kwargs: object) -> setup.PrivacySetupReport:
        calls.append(kwargs)
        return setup.PrivacySetupReport("configured", "minimal_external", grant_state="granted")

    monkeypatch.setattr(setup, "_interactive_terminal", lambda: True)
    monkeypatch.setattr(setup, "get_privacy_setup_snapshot", snapshot)
    monkeypatch.setattr(setup, "_propose", never)
    monkeypatch.setattr(setup, "run_privacy_setup", run_setup)
    report = asyncio.run(setup.run_credential_heuristic_change(CredentialHeuristic.DISABLED))
    assert report.outcome == "configured"
    assert len(calls) == 1
    assert calls[0]["credential_heuristic"] is CredentialHeuristic.DISABLED


def test_setup_drafts_the_grant_with_the_requested_filter_setting() -> None:
    current = _policy()
    answers = setup.recipe_answers("private", current, None)
    candidate = setup.build_candidate_policy(
        replace(current, credential_heuristic=CredentialHeuristic.DISABLED),
        answers,
        now=_NOW,
    )
    assert candidate.credential_heuristic is CredentialHeuristic.DISABLED


def test_disable_when_already_off_is_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    async def snapshot(_locator: object = None) -> setup.PrivacySetupSnapshot:
        return _snapshot(_policy(CredentialHeuristic.DISABLED))

    monkeypatch.setattr(setup, "_interactive_terminal", lambda: True)
    monkeypatch.setattr(setup, "get_privacy_setup_snapshot", snapshot)
    report = asyncio.run(setup.run_credential_heuristic_change(CredentialHeuristic.DISABLED))
    assert report.outcome == "unchanged"


def test_enable_restores_the_filter_for_this_repository_without_a_terminal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Owner decision 2026-10-07: enable is per repository, the reverse of disable."""

    proposed: list[PrivacyPolicy] = []

    async def snapshot(_locator: object = None) -> setup.PrivacySetupSnapshot:
        return _snapshot(_policy(CredentialHeuristic.DISABLED))

    async def propose(candidate: PrivacyPolicy, digest: str, **_: object) -> None:
        assert digest == _AUTHORITY
        proposed.append(candidate)
        return None  # the service applied it as a tightening of this grant

    async def no_machine(*_: object, **__: object) -> None:
        raise AssertionError("a repository enable never touches the installation default")

    monkeypatch.setattr(setup, "_interactive_terminal", lambda: False)
    monkeypatch.setattr(setup, "get_privacy_setup_snapshot", snapshot)
    monkeypatch.setattr(setup, "_propose", propose)
    monkeypatch.setattr(setup, "_tighten_machine", no_machine)
    report = asyncio.run(setup.run_credential_heuristic_change(CredentialHeuristic.ENFORCED))
    assert report.outcome == "configured"
    assert [policy.credential_heuristic for policy in proposed] == [CredentialHeuristic.ENFORCED]
    assert not any(
        change.widens
        for change in privacy_policy_changes(_policy(CredentialHeuristic.DISABLED), proposed[0])
    )


def test_enable_without_a_grant_has_nothing_to_restore(monkeypatch: pytest.MonkeyPatch) -> None:
    async def snapshot(_locator: object = None) -> setup.PrivacySetupSnapshot:
        return _snapshot(_policy(), grant="missing")

    monkeypatch.setattr(setup, "get_privacy_setup_snapshot", snapshot)
    report = asyncio.run(setup.run_credential_heuristic_change(CredentialHeuristic.ENFORCED))
    assert (report.outcome, report.reason) == ("unchanged", "repository_privacy_grant_missing")


def test_machine_default_enable_tightens_and_disable_needs_the_ceremony(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tightened: list[tuple[PrivacyPolicy, str]] = []
    proposed: list[PrivacyPolicy] = []
    machine = {"policy": _policy(CredentialHeuristic.DISABLED)}

    async def effective() -> PrivacyPolicy:
        return machine["policy"]

    async def tighten(candidate: PrivacyPolicy, expected: str) -> None:
        tightened.append((candidate, expected))

    async def propose(candidate: PrivacyPolicy, expected: str) -> str:
        assert expected == _DIGEST
        proposed.append(candidate)
        return "ppr_10000000-0000-4000-8000-000000000009"

    async def decide(_proposal_id: str) -> object:
        return SimpleNamespace(status="committed")

    monkeypatch.setattr(setup, "_interactive_terminal", lambda: False)
    monkeypatch.setattr(setup, "_machine_effective_policy", effective)
    monkeypatch.setattr(setup, "_tighten_machine", tighten)
    monkeypatch.setattr(setup, "_propose_machine", propose)
    monkeypatch.setattr(setup, "_decide", decide)
    enabled = asyncio.run(
        setup.run_credential_heuristic_change(CredentialHeuristic.ENFORCED, machine_default=True)
    )
    assert enabled.outcome == "configured"
    assert tightened[0][0].credential_heuristic is CredentialHeuristic.ENFORCED

    machine["policy"] = _policy()
    refused = asyncio.run(
        setup.run_credential_heuristic_change(CredentialHeuristic.DISABLED, machine_default=True)
    )
    assert refused.reason == "local_terminal_required"
    monkeypatch.setattr(setup, "_interactive_terminal", lambda: True)
    disabled = asyncio.run(
        setup.run_credential_heuristic_change(CredentialHeuristic.DISABLED, machine_default=True)
    )
    assert disabled.outcome == "configured"
    assert [policy.credential_heuristic for policy in proposed] == [CredentialHeuristic.DISABLED]


def test_cli_command_is_registered_with_both_directions(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[CredentialHeuristic] = []
    scopes: list[bool] = []

    async def change(
        setting: CredentialHeuristic, *, machine_default: bool = False, **_: object
    ) -> setup.PrivacySetupReport:
        seen.append(setting)
        scopes.append(machine_default)
        return setup.PrivacySetupReport("configured", "local_only")

    monkeypatch.setattr(setup, "run_credential_heuristic_change", change)
    runner = CliRunner()
    for action in ("disable", "enable"):
        result = runner.invoke(app, ["privacy", "credential-heuristic", action, "--json"])
        assert result.exit_code == 0, result.output
    assert seen == [CredentialHeuristic.DISABLED, CredentialHeuristic.ENFORCED]
    result = runner.invoke(
        app, ["privacy", "credential-heuristic", "enable", "--machine-default", "--json"]
    )
    assert result.exit_code == 0, result.output
    assert scopes == [False, False, True]
    rejected = runner.invoke(app, ["privacy", "credential-heuristic", "off"])
    assert rejected.exit_code != 0


def test_privacy_show_labels_the_installation_default() -> None:
    from yoetz.adapters.privacy.catalog import encode_privacy_policy_json
    from yoetz.cli.app import (
        _effective_credential_heuristic_line,  # pyright: ignore[reportPrivateUsage]
    )

    machine = encode_privacy_policy_json(_policy(CredentialHeuristic.DISABLED))
    line = _effective_credential_heuristic_line({"policy": machine})
    assert line is not None
    assert line.startswith("Possible-credential filter, installation default: off")
    assert "enable --machine-default" in line
    repository = dict(machine)
    repository["effective_scope"] = {
        "kind": "workspace",
        "installation_id": _INSTALLATION,
        "workspace_ref_commitment": "hmac-sha256:" + "1" * 64,
    }
    repo_line = _effective_credential_heuristic_line({"policy": repository})
    assert repo_line is not None and repo_line.startswith(
        "Possible-credential filter for this repository: off"
    )
    enforced = encode_privacy_policy_json(_policy())
    assert _effective_credential_heuristic_line({"policy": enforced}) is None
    assert _effective_credential_heuristic_line({}) is None


def test_the_terminal_interface_shows_the_shared_pair(monkeypatch: pytest.MonkeyPatch) -> None:
    from contextlib import asynccontextmanager

    from yoetz.tui.runtime import YoetzRuntime

    async def posture(response: object) -> object:
        class _Client:
            async def privacy_get_setup(self, _body: object) -> object:
                return response

        @asynccontextmanager
        async def connect(_self: YoetzRuntime):  # noqa: ANN202
            yield _Client()

        monkeypatch.setattr(YoetzRuntime, "_client", connect)
        return await YoetzRuntime().privacy_posture()

    from yoetz.adapters.privacy.catalog import encode_privacy_policy_json

    composed = encode_privacy_policy_json(_policy(CredentialHeuristic.DISABLED))
    current = asyncio.run(
        posture(
            {
                "composed_policy": composed,
                "grant_state": "missing",
                "credential_heuristic": {"repository": "enforced", "machine_default": "disabled"},
            }
        )
    )
    assert getattr(current, "credential_heuristic") == ("enforced", "disabled")
    assert getattr(current, "credential_heuristic_disabled") is False
    summary = getattr(current, "credential_heuristic_summary")
    assert "enable --machine-default" in summary and "Turn it back on here" not in summary
    plain = asyncio.run(
        posture(
            {
                "composed_policy": encode_privacy_policy_json(_policy()),
                "credential_heuristic": {"repository": "enforced", "machine_default": "enforced"},
            }
        )
    )
    assert getattr(plain, "credential_heuristic_summary") is None


def test_enable_without_a_grant_explains_the_machine_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def change(setting: CredentialHeuristic, **_: object) -> setup.PrivacySetupReport:
        del setting
        return setup.PrivacySetupReport(
            "unchanged", "local_only", reason="repository_privacy_grant_missing"
        )

    monkeypatch.setattr(setup, "run_credential_heuristic_change", change)
    result = CliRunner().invoke(app, ["privacy", "credential-heuristic", "enable"])
    assert result.exit_code == 0, result.output
    assert "enable --machine-default" in result.output
    assert "no privacy grant" in result.output
