"""``yoetz privacy credential-heuristic`` (issue #982 owner opt-out): the way in and the way out."""

from __future__ import annotations

import asyncio
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


def test_disable_needs_a_local_terminal_and_a_repository_grant(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(setup, "_interactive_terminal", lambda: False)
    report = asyncio.run(setup.run_credential_heuristic_change(CredentialHeuristic.DISABLED))
    assert (report.outcome, report.reason) == ("failed", "local_terminal_required")

    async def snapshot(_locator: object = None) -> setup.PrivacySetupSnapshot:
        return _snapshot(_policy(), grant="missing")

    async def never(*_: object, **__: object) -> str:
        raise AssertionError("must not propose without a repository grant")

    monkeypatch.setattr(setup, "_interactive_terminal", lambda: True)
    monkeypatch.setattr(setup, "get_privacy_setup_snapshot", snapshot)
    monkeypatch.setattr(setup, "_propose", never)
    report = asyncio.run(setup.run_credential_heuristic_change(CredentialHeuristic.DISABLED))
    assert (report.outcome, report.reason) == ("failed", "repository_privacy_grant_missing")


def test_disable_when_already_off_is_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    async def snapshot(_locator: object = None) -> setup.PrivacySetupSnapshot:
        return _snapshot(_policy(CredentialHeuristic.DISABLED))

    monkeypatch.setattr(setup, "_interactive_terminal", lambda: True)
    monkeypatch.setattr(setup, "get_privacy_setup_snapshot", snapshot)
    report = asyncio.run(setup.run_credential_heuristic_change(CredentialHeuristic.DISABLED))
    assert report.outcome == "unchanged"


def test_enable_is_a_direct_machine_tightening_without_a_terminal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tightened: list[tuple[PrivacyPolicy, str]] = []

    async def machine() -> PrivacyPolicy:
        return _policy(CredentialHeuristic.DISABLED)

    async def tighten(candidate: PrivacyPolicy, expected: str) -> None:
        tightened.append((candidate, expected))

    monkeypatch.setattr(setup, "_interactive_terminal", lambda: False)
    monkeypatch.setattr(setup, "_machine_effective_policy", machine)
    monkeypatch.setattr(setup, "_tighten_machine", tighten)
    report = asyncio.run(setup.run_credential_heuristic_change(CredentialHeuristic.ENFORCED))
    assert report.outcome == "configured"
    assert len(tightened) == 1
    candidate, expected = tightened[0]
    assert expected == _DIGEST
    assert candidate.credential_heuristic is CredentialHeuristic.ENFORCED
    assert not any(
        change.widens
        for change in privacy_policy_changes(_policy(CredentialHeuristic.DISABLED), candidate)
    )

    async def already_on() -> PrivacyPolicy:
        return _policy()

    monkeypatch.setattr(setup, "_machine_effective_policy", already_on)
    report = asyncio.run(setup.run_credential_heuristic_change(CredentialHeuristic.ENFORCED))
    assert report.outcome == "unchanged"
    assert len(tightened) == 1


def test_cli_command_is_registered_with_both_directions(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[CredentialHeuristic] = []

    async def change(setting: CredentialHeuristic, **_: object) -> setup.PrivacySetupReport:
        seen.append(setting)
        return setup.PrivacySetupReport("configured", "local_only")

    monkeypatch.setattr(setup, "run_credential_heuristic_change", change)
    runner = CliRunner()
    for action in ("disable", "enable"):
        result = runner.invoke(app, ["privacy", "credential-heuristic", action, "--json"])
        assert result.exit_code == 0, result.output
    assert seen == [CredentialHeuristic.DISABLED, CredentialHeuristic.ENFORCED]
    rejected = runner.invoke(app, ["privacy", "credential-heuristic", "off"])
    assert rejected.exit_code != 0


def test_privacy_show_and_the_terminal_interface_say_when_the_filter_is_off(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from contextlib import asynccontextmanager

    from yoetz.adapters.privacy.catalog import encode_privacy_policy_json
    from yoetz.cli.app import (
        _effective_credential_heuristic_line,  # pyright: ignore[reportPrivateUsage]
    )
    from yoetz.tui.runtime import YoetzRuntime

    disabled = encode_privacy_policy_json(_policy(CredentialHeuristic.DISABLED))
    enforced = encode_privacy_policy_json(_policy())
    line = _effective_credential_heuristic_line({"policy": disabled})
    assert line is not None and line.startswith("Possible-credential filter: off")
    assert _effective_credential_heuristic_line({"policy": enforced}) is None
    assert _effective_credential_heuristic_line({}) is None

    async def posture(composed: object) -> bool:
        class _Client:
            async def privacy_get_setup(self, _body: object) -> object:
                return {"composed_policy": composed}

        @asynccontextmanager
        async def connect(_self: YoetzRuntime):  # noqa: ANN202
            yield _Client()

        monkeypatch.setattr(YoetzRuntime, "_client", connect)
        return (await YoetzRuntime().privacy_posture()).credential_heuristic_disabled

    assert asyncio.run(posture(disabled)) is True
    assert asyncio.run(posture(enforced)) is False
